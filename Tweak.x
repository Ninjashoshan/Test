// TwLog 0.1.0
// Logs the Twitter app's (com.atebits.Tweetie2) network and web view activity
// to the system log with the prefix "[TwLog]".
//
// Privacy: query VALUES, request bodies, cookies and Authorization headers are
// never logged. Only scheme/host/path, query parameter NAMES, status codes,
// error codes, and (for HTTP errors >= 400) the first 300 bytes of the
// response body are written.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <substrate.h>

#define TLOG(fmt, ...) NSLog(@"[TwLog] " fmt, ##__VA_ARGS__)

typedef void (^TLCompletion)(NSData *, NSURLResponse *, NSError *);

#pragma mark - Helpers

static NSString *safeURL(NSURL *u) {
    if (!u) return @"(nil)";
    NSURLComponents *c = [NSURLComponents componentsWithURL:u resolvingAgainstBaseURL:NO];
    if (!c) return @"(unparsable)";
    NSMutableArray *names = [NSMutableArray array];
    for (NSURLQueryItem *q in c.queryItems) [names addObject:q.name ?: @"?"];
    NSString *base = [NSString stringWithFormat:@"%@://%@%@", c.scheme ?: @"?", c.host ?: @"", c.path ?: @""];
    if (names.count) return [base stringByAppendingFormat:@" ?[%@]", [names componentsJoinedByString:@","]];
    return base;
}

static NSString *headerOf(NSURLRequest *req, NSString *name, NSUInteger max) {
    NSString *v = [req valueForHTTPHeaderField:name];
    if (!v) return @"-";
    return v.length > max ? [v substringToIndex:max] : v;
}

static long statusOf(NSURLResponse *r) {
    return [r isKindOfClass:[NSHTTPURLResponse class]] ? (long)((NSHTTPURLResponse *)r).statusCode : -1;
}

static NSString *errStr(NSError *e) {
    if (!e) return @"none";
    NSString *s = [NSString stringWithFormat:@"%@ %ld", e.domain, (long)e.code];
    NSString *f = e.userInfo[@"NSErrorFailingURLStringKey"];
    if ([f isKindOfClass:[NSString class]]) s = [s stringByAppendingFormat:@" failingURL=%@", safeURL([NSURL URLWithString:f])];
    return s;
}

static NSString *bodyPreview(NSData *d, NSUInteger n) {
    if (!d.length) return @"(empty)";
    NSData *s = [d subdataWithRange:NSMakeRange(0, MIN(n, d.length))];
    if (memchr(s.bytes, 0, s.length)) return [NSString stringWithFormat:@"(%lu bytes, binary)", (unsigned long)d.length];
    NSString *t = [[NSString alloc] initWithData:s encoding:NSUTF8StringEncoding]
               ?: [[NSString alloc] initWithData:s encoding:NSISOLatin1StringEncoding];
    t = [t stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    t = [t stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
    return t ?: @"(undecodable)";
}

// Track the replacement IMPs we install so we never hook the same method twice
// (e.g. a subclass that merely inherits a method we already hooked).
static NSMutableSet *gReps;

static BOOL alreadyHooked(Class c, SEL s) {
    IMP cur = class_getMethodImplementation(c, s);
    @synchronized (gReps) {
        return [gReps containsObject:[NSValue valueWithPointer:(void *)cur]];
    }
}

static void noteRep(IMP rep) {
    @synchronized (gReps) {
        [gReps addObject:[NSValue valueWithPointer:(void *)rep]];
    }
}

static BOOL canHook(Class c, SEL s) {
    return c && class_getInstanceMethod(c, s) && !alreadyHooked(c, s);
}

#pragma mark - NSURLSession: completion-handler tasks

static TLCompletion wrapCompletion(NSString *tag, NSURLRequest *req, TLCompletion h) {
    NSString *u = safeURL(req.URL);
    return ^(NSData *data, NSURLResponse *resp, NSError *err) {
        long st = statusOf(resp);
        TLOG(@"[resp] %@ status=%ld err=%@ bytes=%lu url=%@", tag, st, errStr(err), (unsigned long)data.length, u);
        if (st >= 400) TLOG(@"[resp-body] %@ %@", u, bodyPreview(data, 300));
        if (h) h(data, resp, err);
    };
}

static void hookSessionClass(Class c) {
    {
        SEL sel = @selector(dataTaskWithRequest:completionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^id(id _self, NSURLRequest *req, TLCompletion h) {
                if (!orig) return nil;
                TLOG(@"[req] dataTask %@ %@ ua=%@ clientver=%@", req.HTTPMethod, safeURL(req.URL),
                     headerOf(req, @"User-Agent", 60), headerOf(req, @"X-Twitter-Client-Version", 20));
                return ((id (*)(id, SEL, id, id))orig)(_self, sel, req, wrapCompletion(@"dataTask", req, h));
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(dataTaskWithURL:completionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^id(id _self, NSURL *url, TLCompletion h) {
                if (!orig) return nil;
                NSURLRequest *req = url ? [NSURLRequest requestWithURL:url] : nil;
                TLOG(@"[req] dataTask(url) GET %@", safeURL(url));
                return ((id (*)(id, SEL, id, id))orig)(_self, sel, url, wrapCompletion(@"dataTask(url)", req, h));
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(uploadTaskWithRequest:fromData:completionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^id(id _self, NSURLRequest *req, NSData *body, TLCompletion h) {
                if (!orig) return nil;
                TLOG(@"[req] uploadTask %@ %@ bodyBytes=%lu ua=%@ clientver=%@", req.HTTPMethod, safeURL(req.URL),
                     (unsigned long)body.length, headerOf(req, @"User-Agent", 60), headerOf(req, @"X-Twitter-Client-Version", 20));
                return ((id (*)(id, SEL, id, id, id))orig)(_self, sel, req, body, wrapCompletion(@"uploadTask", req, h));
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
}

#pragma mark - NSURLSession: delegate-based tasks

static void logTask(NSString *tag, NSURLSessionTask *t, NSString *extra) {
    NSURLRequest *r = t.currentRequest ?: t.originalRequest;
    TLOG(@"[%@] %@ %@ ua=%@ clientver=%@ %@", tag, r.HTTPMethod ?: @"?", safeURL(r.URL),
         headerOf(r, @"User-Agent", 60), headerOf(r, @"X-Twitter-Client-Version", 20), extra ?: @"");
}

static void hookDelegateClass(Class c) {
    static NSMutableSet *done;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ done = [NSMutableSet set]; });
    @synchronized (done) {
        if ([done containsObject:c]) return;
        [done addObject:c];
    }
    TLOG(@"[hook] session delegate class %s", class_getName(c));

    // Task finished (this is where -999 / timeouts / TLS errors show up).
    {
        SEL sel = @selector(URLSession:task:didCompleteWithError:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, NSURLSession *s, NSURLSessionTask *t, NSError *e) {
                logTask(@"done", t, [NSString stringWithFormat:@"status=%ld err=%@", statusOf(t.response), errStr(e)]);
                if (orig) ((void (*)(id, SEL, id, id, id))orig)(_self, sel, s, t, e);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    // Response headers received.
    {
        SEL sel = @selector(URLSession:dataTask:didReceiveResponse:completionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, NSURLSession *s, NSURLSessionDataTask *t, NSURLResponse *r, id handler) {
                logTask(@"resp", t, [NSString stringWithFormat:@"status=%ld mime=%@ len=%lld", statusOf(r), r.MIMEType, r.expectedContentLength]);
                if (orig) ((void (*)(id, SEL, id, id, id, id))orig)(_self, sel, s, t, r, handler);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    // Body of failed responses (error JSON), first 300 bytes only.
    {
        SEL sel = @selector(URLSession:dataTask:didReceiveData:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, NSURLSession *s, NSURLSessionDataTask *t, NSData *d) {
                long st = statusOf(t.response);
                if (st >= 400) {
                    NSURLRequest *r = t.currentRequest ?: t.originalRequest;
                    TLOG(@"[resp-body] status=%ld %@ %@", st, safeURL(r.URL), bodyPreview(d, 300));
                }
                if (orig) ((void (*)(id, SEL, id, id, id))orig)(_self, sel, s, t, d);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    // Redirects.
    {
        SEL sel = @selector(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, NSURLSession *s, NSURLSessionTask *t, NSHTTPURLResponse *resp,
                                                    NSURLRequest *newReq, void (^handler)(NSURLRequest *)) {
                logTask(@"redirect", t, [NSString stringWithFormat:@"status=%ld to=%@", (long)resp.statusCode, safeURL(newReq.URL)]);
                void (^w)(NSURLRequest *) = ^(NSURLRequest *r) {
                    if (!r) TLOG(@"[redirect] app CANCELLED the redirect to %@", safeURL(newReq.URL));
                    if (handler) handler(r);
                };
                if (orig) ((void (*)(id, SEL, id, id, id, id, id))orig)(_self, sel, s, t, resp, newReq, w);
                else if (handler) handler(newReq);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    // Certificate / auth challenges (session level). disposition: 0=use credential, 1=default handling,
    // 2=cancel challenge, 3=reject protection space.
    {
        SEL sel = @selector(URLSession:didReceiveChallenge:completionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, NSURLSession *s, NSURLAuthenticationChallenge *ch,
                                                    void (^handler)(NSInteger, NSURLCredential *)) {
                NSString *host = ch.protectionSpace.host;
                NSString *method = ch.protectionSpace.authenticationMethod;
                void (^w)(NSInteger, NSURLCredential *) = ^(NSInteger d, NSURLCredential *cr) {
                    TLOG(@"[challenge] host=%@ method=%@ -> disposition=%ld credential=%d", host, method, (long)d, cr != nil);
                    if (handler) handler(d, cr);
                };
                if (orig) ((void (*)(id, SEL, id, id, id))orig)(_self, sel, s, ch, w);
                else if (handler) handler(1, nil);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    // Certificate / auth challenges (task level).
    {
        SEL sel = @selector(URLSession:task:didReceiveChallenge:completionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, NSURLSession *s, NSURLSessionTask *t, NSURLAuthenticationChallenge *ch,
                                                    void (^handler)(NSInteger, NSURLCredential *)) {
                NSString *host = ch.protectionSpace.host;
                NSString *method = ch.protectionSpace.authenticationMethod;
                NSString *u = safeURL((t.currentRequest ?: t.originalRequest).URL);
                void (^w)(NSInteger, NSURLCredential *) = ^(NSInteger d, NSURLCredential *cr) {
                    TLOG(@"[challenge] host=%@ method=%@ task=%@ -> disposition=%ld credential=%d", host, method, u, (long)d, cr != nil);
                    if (handler) handler(d, cr);
                };
                if (orig) ((void (*)(id, SEL, id, id, id, id))orig)(_self, sel, s, t, ch, w);
                else if (handler) handler(1, nil);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
}

// Sessions created with a delegate: discover the delegate class and hook it.
static void hookSessionFactory(void) {
    Class meta = object_getClass([NSURLSession class]);
    SEL sel = @selector(sessionWithConfiguration:delegate:delegateQueue:);
    if (!class_getInstanceMethod(meta, sel)) return;
    __block IMP orig = NULL;
    IMP rep = imp_implementationWithBlock(^id(id _cls, NSURLSessionConfiguration *cfg, id delegate, NSOperationQueue *q) {
        if (delegate) hookDelegateClass(object_getClass(delegate));
        if (!orig) return nil;
        return ((id (*)(id, SEL, id, id, id))orig)(_cls, sel, cfg, delegate, q);
    });
    MSHookMessageEx(meta, sel, rep, &orig);
    noteRep(rep);
}

#pragma mark - WKWebView navigation delegate

static void hookNavDelegateClass(Class c) {
    static NSMutableSet *done;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ done = [NSMutableSet set]; });
    @synchronized (done) {
        if ([done containsObject:c]) return;
        [done addObject:c];
    }
    TLOG(@"[hook] web navigation delegate class %s", class_getName(c));

    {
        SEL sel = @selector(webView:decidePolicyForNavigationAction:decisionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, WKWebView *wv, WKNavigationAction *a, void (^handler)(NSInteger)) {
                NSString *u = safeURL(a.request.URL);
                TLOG(@"[web] action url=%@ type=%ld mainFrame=%d", u, (long)a.navigationType, (int)a.targetFrame.mainFrame);
                void (^w)(NSInteger) = ^(NSInteger p) {
                    TLOG(@"[web] action policy=%ld (0=cancel,1=allow) for %@", (long)p, u);
                    if (handler) handler(p);
                };
                if (orig) ((void (*)(id, SEL, id, id, id))orig)(_self, sel, wv, a, w);
                else if (handler) handler(1);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(webView:decidePolicyForNavigationResponse:decisionHandler:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, WKWebView *wv, WKNavigationResponse *r, void (^handler)(NSInteger)) {
                NSString *u = safeURL(r.response.URL);
                TLOG(@"[web] response status=%ld url=%@ mainFrame=%d mime=%@", statusOf(r.response), u,
                     (int)r.forMainFrame, r.response.MIMEType);
                void (^w)(NSInteger) = ^(NSInteger p) {
                    TLOG(@"[web] response policy=%ld (0=cancel,1=allow) for %@", (long)p, u);
                    if (handler) handler(p);
                };
                if (orig) ((void (*)(id, SEL, id, id, id))orig)(_self, sel, wv, r, w);
                else if (handler) handler(1);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(webView:didReceiveServerRedirectForProvisionalNavigation:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, WKWebView *wv, WKNavigation *n) {
                TLOG(@"[web] server redirect, now at %@", safeURL(wv.URL));
                if (orig) ((void (*)(id, SEL, id, id))orig)(_self, sel, wv, n);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(webView:didCommitNavigation:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, WKWebView *wv, WKNavigation *n) {
                TLOG(@"[web] committed %@", safeURL(wv.URL));
                if (orig) ((void (*)(id, SEL, id, id))orig)(_self, sel, wv, n);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(webView:didFinishNavigation:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, WKWebView *wv, WKNavigation *n) {
                TLOG(@"[web] finished %@", safeURL(wv.URL));
                if (orig) ((void (*)(id, SEL, id, id))orig)(_self, sel, wv, n);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(webView:didFailProvisionalNavigation:withError:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, WKWebView *wv, WKNavigation *n, NSError *e) {
                TLOG(@"[web] FAILED (provisional) at %@ err=%@", safeURL(wv.URL), errStr(e));
                if (orig) ((void (*)(id, SEL, id, id, id))orig)(_self, sel, wv, n, e);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(webView:didFailNavigation:withError:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, WKWebView *wv, WKNavigation *n, NSError *e) {
                TLOG(@"[web] FAILED at %@ err=%@", safeURL(wv.URL), errStr(e));
                if (orig) ((void (*)(id, SEL, id, id, id))orig)(_self, sel, wv, n, e);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
}

%hook WKWebView

- (void)setNavigationDelegate:(id)delegate {
    if (delegate) hookNavDelegateClass(object_getClass(delegate));
    %orig;
}

- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    TLOG(@"[web] loadRequest %@ ua=%@", safeURL(request.URL), headerOf(request, @"User-Agent", 60));
    return %orig;
}

%end

%hook UIApplication

- (BOOL)openURL:(NSURL *)url {
    TLOG(@"[app] openURL %@", safeURL(url));
    return %orig;
}

- (void)openURL:(NSURL *)url options:(NSDictionary *)options completionHandler:(void (^)(BOOL))completion {
    TLOG(@"[app] openURL(options) %@", safeURL(url));
    %orig;
}

%end

#pragma mark - Init

%ctor {
    @autoreleasepool {
        gReps = [NSMutableSet set];
        TLOG(@"loaded in %@ version %@", [[NSBundle mainBundle] bundleIdentifier],
             [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]);

        Class shared = object_getClass([NSURLSession sharedSession]);
        hookSessionClass([NSURLSession class]);
        if (shared && shared != [NSURLSession class]) hookSessionClass(shared);
        hookSessionFactory();

        %init;
    }
}
