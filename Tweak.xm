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

// Master switch for the experiment. When YES, any server-selected sp == "s2k"
// is rewritten to "s2k_fo" before akd reads it, forcing the hex-encoded PBKDF2
// derivation. Flip to NO to go back to pure logging.
static const BOOL kGSAForceS2KFO = YES;

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
    }
}
