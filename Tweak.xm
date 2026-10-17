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

static NSString * const kLogPath = @"/tmp/gsa_debug.log";
static NSObject *gLogLock;

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

    @synchronized (gLogLock) {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:kLogPath];
        if (!fh) {
            [[NSFileManager defaultManager] createFileAtPath:kLogPath
                                                    contents:nil
                                                  attributes:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:kLogPath];
        }
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
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
// plists; NSPropertyListSerialization reads both.
static id GSAPlistFromData(NSData *data) {
    if (![data isKindOfClass:[NSData class]] || [data length] == 0) return nil;
    NSError *err = nil;
    id obj = [NSPropertyListSerialization propertyListWithData:data
                                                       options:NSPropertyListImmutable
                                                        format:NULL
                                                         error:&err];
    return obj; // nil if not a plist (e.g. still encrypted) — caller handles
}

// ---- hooks -----------------------------------------------------------------
//
// The exact AIAS method signatures differ slightly across point releases, so
// rather than %hook a fixed prototype we swizzle at runtime by selector name.
// We wrap three things:
//   1. the request dictionary just before it's sent
//   2. the response dictionary just after it's parsed
//   3. the raw bytes handed to didReceiveData: (fallback if 1/2 are opaque)

%hookf(void, "noop") { } // keeps Logos happy if no static %hook is emitted

%ctor {
    @autoreleasepool {
        gLogLock = [[NSObject alloc] init];
        GSALog(@"==== GSALogger loaded in pid %d (%@) ====",
               getpid(),
               [[NSProcessInfo processInfo] processName]);

        // Only do real work inside akd.
        NSString *proc = [[NSProcessInfo processInfo] processName];
        if (![proc isEqualToString:@"akd"]) return;

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
                        id plist = GSAPlistFromData(data);
                        if (plist) {
                            GSALog(@"--- RESPONSE (%lu bytes, parsed) ---\n%@",
                                   (unsigned long)[data length], GSADescribe(plist));
                        } else {
                            GSALog(@"--- RESPONSE (%lu bytes, opaque/not-plist) ---\n%@",
                                   (unsigned long)[data length],
                                   [data description]); // hex-ish dump from NSData
                        }
                        ((void(*)(id,SEL,id,id,NSData*))orig)(self_, sel, session, task, data);
                    }));
                GSALog(@"hooked -[AIASSession URLSession:dataTask:didReceiveData:]");
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
