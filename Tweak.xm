// GSALogger — dumps the GrandSlam SRP request/response plists that akd
// exchanges with Apple's auth servers, so the M2-mismatch can be diagnosed
// from the actual fields instead of guessed at.
//
// Target:  akd  (iOS 10.3.3, arm64)
// Hooks:   AppleIDAuthSupport's request/response path
// Output:  /tmp/gsa_debug.log  (appended, one block per request)
//
// The class/selector names below are the ones that appear in your syslog:
//   akd(AppleIDAuthSupport): SendRequestAndCreateResponse: ...
//   -[AIASSession URLSession:dataTask:didReceiveData:]
// AIAS* lives in AppleIDAuthSupport.framework. We resolve the classes at
// runtime with %c so the tweak loads even if a symbol is absent on this build.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSObject *gLogLock;
static NSString *gLogPath;   // chosen at load time from candidates below

// akd runs in a tight sandbox; /tmp is often not writable. Pick the first
// path we can actually create a file in. Whatever we pick is printed to
// syslog at load so you know where to look.
static NSString *GSAChooseLogPath(void) {
    NSArray *candidates = @[
        @"/var/mobile/gsa_debug.log",
        @"/var/root/gsa_debug.log",
        @"/var/tmp/gsa_debug.log",
        @"/tmp/gsa_debug.log",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in candidates) {
        if ([fm createFileAtPath:p contents:nil attributes:nil]) return p;
    }
    return nil; // nothing writable — we'll rely on syslog only
}

// ---- logging helpers -------------------------------------------------------

static void GSALog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"%@  %@\n",
                      [df stringFromDate:[NSDate date]], msg];

    // Always mirror to syslog, prefixed so you can grep "GSALOG" out of the
    // normal device log even if no file path is writable.
    NSLog(@"GSALOG %@", msg);

    @synchronized (gLogLock) {
        if (!gLogPath) return; // syslog-only mode
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
        if (!fh) {
            [[NSFileManager defaultManager] createFileAtPath:gLogPath
                                                    contents:nil
                                                  attributes:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
        }
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    }
}

// Pretty-print any plist-ish object. SRP blobs come through as NSData; render
// them as hex so B / M1 / salt are directly comparable across attempts.
static NSString *GSADescribe(id obj) {
    if ([obj isKindOfClass:[NSData class]]) {
        const unsigned char *b = (const unsigned char *)[(NSData *)obj bytes];
        NSUInteger len = [(NSData *)obj length];
        NSMutableString *hex = [NSMutableString stringWithCapacity:len * 2 + 16];
        [hex appendFormat:@"<%lu bytes> ", (unsigned long)len];
        for (NSUInteger i = 0; i < len; i++) [hex appendFormat:@"%02x", b[i]];
        return hex;
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableString *s = [NSMutableString stringWithString:@"{\n"];
        for (id k in (NSDictionary *)obj) {
            [s appendFormat:@"    %@ = %@\n", k, GSADescribe(((NSDictionary *)obj)[k])];
        }
        [s appendString:@"  }"];
        return s;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableString *s = [NSMutableString stringWithString:@"[\n"];
        for (id v in (NSArray *)obj) [s appendFormat:@"    %@\n", GSADescribe(v)];
        [s appendString:@"  ]"];
        return s;
    }
    return [obj description];
}

// Try to turn a raw HTTP body into a plist dict. GSA bodies are XML or binary
// plists; NSPropertyListSerialization reads both. We ask for a MUTABLE container
// so we can rewrite sp in place when patching is on.
static id GSAPlistFromData(NSData *data, NSPropertyListFormat *outFmt) {
    if (![data isKindOfClass:[NSData class]] || [data length] == 0) return nil;
    NSError *err = nil;
    id obj = [NSPropertyListSerialization
                 propertyListWithData:data
                              options:NSPropertyListMutableContainersAndLeaves
                               format:outFmt
                                error:&err];
    return obj; // nil if not a plist (e.g. still encrypted) — caller handles
}

// Master switch for the old experiment (sp rewrite). Abandoned — the working
// 12.5 device also uses sp=s2k, so this was never the issue. Kept OFF.
static const BOOL kGSAForceS2KFO = NO;

// THE REAL FIX.
// A working device (iOS 12.5) sends the account DSID as the SRP username `u`;
// this freshly-restored 10.3.3 device sends the email address instead, so the
// SRP proof is computed over the wrong username and the server rejects it
// ("M2 missing" / -36607 / -22406). We rewrite the OUTGOING request body so
// `u` carries the DSID, matching what the account's verifier expects.
// Body-level username rewrite. OFF now — it patches `u` AFTER M1 is built over
// the email, so the server sees a DSID that doesn't match the proof. Superseded
// by altDSID injection below, which fixes the identity BEFORE the proof.
static const BOOL kGSAFixUsername = NO;

// The email akd currently sends, and the DSID it should send instead.
// (DSID captured from the working 12.5 login for this same account.)
static NSString * const kGSAEmail = @"aq_artix2@yahoo.com";
static NSString * const kGSADSID  = @"000025-08-7ce934f8-83af-4aee-b25f-243520e5c2c8";

// In an outgoing GSA request, replace Request.u (== the email) with the DSID.
// Returns YES if it changed something. Mutates the dict in place.
static BOOL GSARewriteUsername(NSMutableDictionary *root) {
    if (![root isKindOfClass:[NSDictionary class]]) return NO;
    id req = root[@"Request"];
    if ([req isKindOfClass:[NSDictionary class]]) {
        id u = ((NSDictionary *)req)[@"u"];
        if ([u isKindOfClass:[NSString class]] &&
            [u caseInsensitiveCompare:kGSAEmail] == NSOrderedSame) {
            ((NSMutableDictionary *)req)[@"u"] = kGSADSID;
            return YES;
        }
    }
    return NO;
}

// ---- altDSID injection -----------------------------------------------------
//
// ROOT CAUSE (from comparing a working iOS 12.5 login to this failing 10.3.3):
// the working device has the account altDSID on its auth context, so akd uses
// the DSID as the SRP username and computes M1 over it. This restored 10.3.3
// device has "No altDSID on context", so akd falls back to the email, computes
// M1 over the email, and the server rejects it. Rewriting the outgoing `u`
// field is too late (M1 is already built over the email). The real fix is to
// supply the altDSID BEFORE the proof is built, by making akd's altDSID
// accessors return the DSID. akd then does the whole SRP exchange over the
// DSID natively, exactly as it did before the restore.

static const BOOL kGSAInjectAltDSID = YES;

// ACCOUNT-SCOPED. We ONLY inject the DSID for the yahoo account, so that
// signing OTHER accounts into iTunes is completely unaffected — akd behaves
// natively for them. The map below is email -> DSID; add a line here if another
// account ever needs the same treatment (capture its DSID from a working
// login first).
static NSDictionary *GSADSIDMap(void) {
    return @{
        @"aq_artix2@yahoo.com" : @"000025-08-7ce934f8-83af-4aee-b25f-243520e5c2c8",
    };
}

// Ask an auth-context / account object for the username it is authenticating.
// Tries the usual AuthKit accessors; returns nil if none respond.
static NSString *GSAContextUsername(id ctx) {
    for (NSString *sn in @[@"username", @"appleID", @"identifier"]) {
        SEL s = NSSelectorFromString(sn);
        if ([ctx respondsToSelector:s]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id v = [ctx performSelector:s];
#pragma clang diagnostic pop
            if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
                return (NSString *)v;
            }
        }
    }
    return nil;
}

// The DSID to inject for THIS context, or nil to leave akd alone. Looks up the
// context's username in the map; only a mapped account gets a DSID.
static NSString *GSAAltDSIDForContext(id ctx) {
    NSString *user = GSAContextUsername(ctx);
    if (!user) return nil;
    NSDictionary *map = GSADSIDMap();
    for (NSString *email in map) {
        if ([user caseInsensitiveCompare:email] == NSOrderedSame) {
            return map[email];
        }
    }
    return nil; // not a mapped account — do nothing, sign in normally
}

// Install an altDSID override on `cls`'s instance method `name`, if it exists.
// Calls through to the original and ONLY substitutes the DSID when the real
// value is nil/empty — i.e. exactly the "No altDSID on context" case. This
// avoids disturbing any flow that already has a correct altDSID.
static void GSAHookAltDSID(Class cls, NSString *clsName, NSString *name) {
    if (!cls) return;
    SEL sel = NSSelectorFromString(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    __block IMP orig = method_setImplementation(m,
        imp_implementationWithBlock(^id(id self_) {
            id real = ((id(*)(id,SEL))orig)(self_, sel);
            BOOL realPopulated = ([real isKindOfClass:[NSString class]] &&
                                  [(NSString *)real length] > 0);
            // SELF-HEAL PROBE: report what akd's own altDSID store returned,
            // for the account being authenticated, before we decide to inject.
            // If this says SELF-HEALED on a later launch, akd persisted the
            // altDSID and the tweak can be removed. If it says EMPTY, the tweak
            // is still doing the work and must stay.
            {
                NSString *who = GSAContextUsername(self_) ?: @"(unknown)";
                GSALog(@"altDSID probe: account=%@ real=%@ via -[%@ %@]",
                       who,
                       realPopulated ? @"SELF-HEALED(populated)" : @"EMPTY(needs tweak)",
                       clsName, name);
            }
            if (realPopulated) {
                return real; // already has one — leave it
            }
            // Empty altDSID. Only inject for a MAPPED account (yahoo). For any
            // other account we return the real (empty) value so akd signs it
            // in normally — this is what keeps other iTunes logins working.
            NSString *dsid = GSAAltDSIDForContext(self_);
            if (dsid) {
                GSALog(@"supplying DSID via -[%@ %@] for mapped account", clsName, name);
                return dsid;
            }
            return real; // not our account — stay out of the way
        }));
    GSALog(@"hooked -[%@ %@] (altDSID, account-scoped)", clsName, name);
}

// Walk the parsed response, find Response.sp (== "s2k"), rewrite to "s2k_fo".
// Returns YES if it changed something. Mutates the dict in place.
static BOOL GSARewriteSP(NSMutableDictionary *root) {
    if (![root isKindOfClass:[NSDictionary class]]) return NO;
    id resp = root[@"Response"];
    if ([resp isKindOfClass:[NSDictionary class]]) {
        id sp = ((NSDictionary *)resp)[@"sp"];
        if ([sp isKindOfClass:[NSString class]] && [sp isEqualToString:@"s2k"]) {
            ((NSMutableDictionary *)resp)[@"sp"] = @"s2k_fo";
            return YES;
        }
    }
    // Some builds place sp at the top level instead of under Response.
    id spTop = root[@"sp"];
    if ([spTop isKindOfClass:[NSString class]] && [spTop isEqualToString:@"s2k"]) {
        root[@"sp"] = @"s2k_fo";
        return YES;
    }
    return NO;
}

// ---- hooks -----------------------------------------------------------------
//
// The exact AIAS method signatures differ slightly across point releases, so
// rather than %hook a fixed prototype we swizzle at runtime by selector name.
// We wrap three things:
//   1. the request dictionary just before it's sent
//   2. the response dictionary just after it's parsed
//   3. the raw bytes handed to didReceiveData: (fallback if 1/2 are opaque)

%ctor {
    @autoreleasepool {
        gLogLock = [[NSObject alloc] init];

        // Only do real work inside akd.
        NSString *proc = [[NSProcessInfo processInfo] processName];
        if (![proc isEqualToString:@"akd"]) return;

        gLogPath = GSAChooseLogPath();
        GSALog(@"==== GSALogger loaded in pid %d (%@); logfile=%@ ====",
               getpid(), proc, gLogPath ?: @"(none - syslog only)");

        // 1 & 2: AIASRequest / AIASSession request+response accessors.
        // Swizzle -[AIASSession URLSession:dataTask:didReceiveData:] to capture
        // raw response bytes, and the request-builder to capture what's sent.
        Class sessionCls = objc_getClass("AIASSession");
        if (sessionCls) {
            SEL sel = @selector(URLSession:dataTask:didReceiveData:);
            Method m = class_getInstanceMethod(sessionCls, sel);
            if (m) {
                __block IMP orig = method_setImplementation(m,
                    imp_implementationWithBlock(^(id self_, id session, id task, NSData *data) {
                        NSData *outData = data; // what we actually pass to akd
                        NSPropertyListFormat fmt = NSPropertyListXMLFormat_v1_0;
                        id plist = GSAPlistFromData(data, &fmt);
                        if (plist) {
                            GSALog(@"--- RESPONSE (%lu bytes, parsed) ---\n%@",
                                   (unsigned long)[data length], GSADescribe(plist));

                            if (kGSAForceS2KFO &&
                                [plist isKindOfClass:[NSDictionary class]]) {
                                if (GSARewriteSP((NSMutableDictionary *)plist)) {
                                    NSError *serr = nil;
                                    NSData *patched = [NSPropertyListSerialization
                                        dataWithPropertyList:plist
                                                      format:fmt
                                                     options:0
                                                       error:&serr];
                                    if (patched) {
                                        outData = patched;
                                        GSALog(@"*** PATCHED sp s2k -> s2k_fo (new %lu bytes) ***\n%@",
                                               (unsigned long)[patched length],
                                               GSADescribe(plist));
                                    } else {
                                        GSALog(@"*** PATCH FAILED to re-serialize: %@ ***",
                                               serr);
                                    }
                                }
                            }
                        } else {
                            GSALog(@"--- RESPONSE (%lu bytes, opaque/not-plist) ---\n%@",
                                   (unsigned long)[data length],
                                   [data description]); // hex-ish dump from NSData
                        }
                        ((void(*)(id,SEL,id,id,NSData*))orig)(self_, sel, session, task, outData);
                    }));
                GSALog(@"hooked -[AIASSession URLSession:dataTask:didReceiveData:] (force s2k_fo = %@)",
                       kGSAForceS2KFO ? @"ON" : @"off");
            } else {
                GSALog(@"WARN: AIASSession has no didReceiveData: on this build");
            }
        } else {
            GSALog(@"WARN: AIASSession class not found");
        }

        // 3: capture the outgoing request dict. On 10.3.x the builder is
        // -[AIASRequest requestDictionary] (or ...plistRepresentation); we hook
        // whichever exists and log its result.
        Class reqCls = objc_getClass("AIASRequest");
        if (reqCls) {
            for (NSString *name in @[@"requestDictionary", @"plistRepresentation",
                                     @"dictionaryRepresentation", @"requestBody"]) {
                SEL sel = NSSelectorFromString(name);
                Method m = class_getInstanceMethod(reqCls, sel);
                if (!m) continue;
                __block IMP orig = method_setImplementation(m,
                    imp_implementationWithBlock(^id(id self_) {
                        id result = ((id(*)(id,SEL))orig)(self_, sel);
                        GSALog(@"--- REQUEST (%@) ---\n%@", name, GSADescribe(result));
                        return result;
                    }));
                GSALog(@"hooked -[AIASRequest %@]", name);
            }
        } else {
            GSALog(@"WARN: AIASRequest class not found");
        }

        // 4: the reliable one — hook -[NSMutableURLRequest setHTTPBody:].
        // Every GSA request body passes through here as a plist, so this
        // captures the client's A and M1 (the proof) regardless of what AIAS's
        // internal selectors are named. This is Experiment A: compare M1 across
        // a patched vs unpatched run — if M1 is identical, akd reused the s2k
        // key and never re-derived under s2k_fo.
        Class reqURLCls = objc_getClass("NSMutableURLRequest");
        if (reqURLCls) {
            SEL sel = @selector(setHTTPBody:);
            Method m = class_getInstanceMethod(reqURLCls, sel);
            if (m) {
                __block IMP orig = method_setImplementation(m,
                    imp_implementationWithBlock(^(id self_, NSData *body) {
                        NSData *outBody = body;
                        NSPropertyListFormat fmt = NSPropertyListXMLFormat_v1_0;
                        id plist = GSAPlistFromData(body, &fmt);
                        if (plist) {
                            GSALog(@"--- HTTPBody REQUEST (%lu bytes) ---\n%@",
                                   (unsigned long)[body length], GSADescribe(plist));

                            if (kGSAFixUsername &&
                                [plist isKindOfClass:[NSDictionary class]]) {
                                if (GSARewriteUsername((NSMutableDictionary *)plist)) {
                                    NSError *serr = nil;
                                    NSData *patched = [NSPropertyListSerialization
                                        dataWithPropertyList:plist
                                                      format:fmt
                                                     options:0
                                                       error:&serr];
                                    if (patched) {
                                        outBody = patched;
                                        GSALog(@"*** PATCHED u email -> DSID (new %lu bytes) ***\n%@",
                                               (unsigned long)[patched length],
                                               GSADescribe(plist));
                                    } else {
                                        GSALog(@"*** USERNAME PATCH re-serialize FAILED: %@ ***",
                                               serr);
                                    }
                                }
                            }
                        }
                        // else: not a plist (token refresh, etc.) — skip quietly
                        ((void(*)(id,SEL,NSData*))orig)(self_, sel, outBody);
                    }));
                GSALog(@"hooked -[NSMutableURLRequest setHTTPBody:] (fix username = %@)",
                       kGSAFixUsername ? @"ON" : @"off");
            }
        }

        // 5: THE FIX — inject the altDSID so akd builds the SRP identity over
        // the DSID (like the working device), instead of falling back to the
        // email after the clean restore wiped the altDSID from its context.
        if (kGSAInjectAltDSID) {
            // Candidate AuthKit classes that carry the account / auth context.
            NSArray *clsNames = @[ @"AKAccount", @"ACAccount",
                                   @"AKAppleIDAuthenticationContext",
                                   @"AKAnisetteData",
                                   @"AKAppleIDAuthenticationController",
                                   @"AKAppleIDAuthenticationService" ];
            // Zero-arg accessors that may return the altDSID.
            NSArray *selNames = @[ @"altDSID", @"aa_altDSID", @"_altDSID",
                                   @"altDSIDForAuthentication", @"DSID" ];
            for (NSString *cn in clsNames) {
                Class c = objc_getClass([cn UTF8String]);
                for (NSString *sn in selNames) {
                    GSAHookAltDSID(c, cn, sn);
                }
            }
            GSALog(@"altDSID injection pass done (value=%@)", kGSADSID);
        }
    }
}
