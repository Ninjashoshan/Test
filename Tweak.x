// TwLog 0.7.0
// 0.5.1 fix: never add a completion handler to a task that did not have one. NSURLSession routes
// handler-less tasks through the same methods with a nil handler; wrapping nil made the app's own
// network layer lose its delegate callbacks (requests hung until they timed out).
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

// Theos builds with -Werror; keep harmless "unused" warnings from failing the build.
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-but-set-variable"

#define TLOG(fmt, ...) NSLog(@"[TwLog] " fmt, ##__VA_ARGS__)

typedef void (^TLCompletion)(NSData *, NSURLResponse *, NSError *);

#pragma mark - Helpers

static NSString *safeURL(NSURL *u) {
    if (!u) return @"(nil)";
    NSURLComponents *c = [NSURLComponents componentsWithURL:u resolvingAgainstBaseURL:NO];
    if (!c) return @"(unparsable)";
    NSMutableArray *names = [NSMutableArray array];
    for (NSURLQueryItem *q in c.queryItems) {
        NSString *n = q.name ?: @"?";
        if ([n isEqualToString:@"flow_name"] && q.value.length && q.value.length < 60) n = [NSString stringWithFormat:@"flow_name=%@", q.value];
        [names addObject:n];
    }
    NSString *base = [NSString stringWithFormat:@"%@://%@%@", c.scheme ?: @"?", c.host ?: @"", c.path ?: @""];
    if (names.count) return [base stringByAppendingFormat:@" ?[%@]", [names componentsJoinedByString:@","]];
    return base;
}

// EXPERIMENT (0.7.0): the app asks Twitter for the "welcome" onboarding flow at launch and the server refuses it.
// Ask for the "login" flow instead, to see whether the server answers it and what the app does with the answer.
static NSURLRequest *rewriteFlow(NSURLRequest *req) {
    NSURL *u = req.URL;
    if (!u || ![u.path hasSuffix:@"/onboarding/task.json"]) return req;
    NSString *abs = u.absoluteString;
    if ([abs rangeOfString:@"flow_name=welcome"].location == NSNotFound) return req;
    NSURL *nu = [NSURL URLWithString:[abs stringByReplacingOccurrencesOfString:@"flow_name=welcome" withString:@"flow_name=login"]];
    if (!nu) return req;
    NSMutableURLRequest *m = [req mutableCopy];
    m.URL = nu;
    TLOG(@"[rewrite] onboarding flow_name welcome -> login");
    return m;
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
                return ((id (*)(id, SEL, id, id))orig)(_self, sel, req, (h ? wrapCompletion(@"dataTask", req, h) : nil));
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
                return ((id (*)(id, SEL, id, id))orig)(_self, sel, url, (h ? wrapCompletion(@"dataTask(url)", req, h) : nil));
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
                req = rewriteFlow(req);
                TLOG(@"[req] uploadTask %@ %@ bodyBytes=%lu ua=%@ clientver=%@", req.HTTPMethod, safeURL(req.URL),
                     (unsigned long)body.length, headerOf(req, @"User-Agent", 60), headerOf(req, @"X-Twitter-Client-Version", 20));
                return ((id (*)(id, SEL, id, id, id))orig)(_self, sel, req, body, (h ? wrapCompletion(@"uploadTask", req, h) : nil));
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(uploadTaskWithRequest:fromData:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^id(id _self, NSURLRequest *req, NSData *body) {
                if (!orig) return nil;
                req = rewriteFlow(req);
                TLOG(@"[req] uploadTask(nohandler) %@ %@ bodyBytes=%lu ua=%@ clientver=%@", req.HTTPMethod, safeURL(req.URL),
                     (unsigned long)body.length, headerOf(req, @"User-Agent", 60), headerOf(req, @"X-Twitter-Client-Version", 20));
                return ((id (*)(id, SEL, id, id))orig)(_self, sel, req, body);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = @selector(dataTaskWithRequest:);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^id(id _self, NSURLRequest *req) {
                if (!orig) return nil;
                req = rewriteFlow(req);
                return ((id (*)(id, SEL, id))orig)(_self, sel, req);
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
                NSURLRequest *r = t.currentRequest ?: t.originalRequest;
                if (st >= 400) {
                    TLOG(@"[resp-body] status=%ld %@ %@", st, safeURL(r.URL), bodyPreview(d, 300));
                } else if ([r.URL.path containsString:@"/onboarding/"]) {
                    NSString *txt = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                    NSMutableArray *ids = [NSMutableArray array];
                    NSRegularExpression *rx = [NSRegularExpression regularExpressionWithPattern:@"\"subtask_id\"\\s*:\\s*\"([^\"]+)\"" options:0 error:nil];
                    for (NSTextCheckingResult *m in [rx matchesInString:txt ?: @"" options:0 range:NSMakeRange(0, txt.length)]) {
                        if (ids.count < 8) [ids addObject:[txt substringWithRange:[m rangeAtIndex:1]]];
                    }
                    TLOG(@"[onboarding] status=%ld bytes=%lu subtasks=[%@]", st, (unsigned long)d.length, [ids componentsJoinedByString:@","]);
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

#pragma mark - All NSURLSession tasks (start + finish), however they were created

static char kStartKey, kDoneKey;

static void hookTaskClass(Class c) {
    {
        SEL sel = @selector(resume);
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self) {
                if ([_self isKindOfClass:[NSURLSessionTask class]] && !objc_getAssociatedObject(_self, &kStartKey)) {
                    objc_setAssociatedObject(_self, &kStartKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                    NSURLSessionTask *t = _self;
                    NSURLRequest *r = t.currentRequest ?: t.originalRequest;
                    TLOG(@"[task-start] %@ %@ %@ bodyBytes=%lu stream=%d ctype=%@ ua=%@ clientver=%@",
                         NSStringFromClass([_self class]), r.HTTPMethod ?: @"?", safeURL(r.URL),
                         (unsigned long)r.HTTPBody.length, (int)(r.HTTPBodyStream != nil),
                         headerOf(r, @"Content-Type", 40), headerOf(r, @"User-Agent", 60),
                         headerOf(r, @"X-Twitter-Client-Version", 20));
                }
                if (orig) ((void (*)(id, SEL))orig)(_self, sel);
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
    {
        SEL sel = NSSelectorFromString(@"setState:");
        if (canHook(c, sel)) {
            __block IMP orig = NULL;
            IMP rep = imp_implementationWithBlock(^(id _self, NSInteger s) {
                if (orig) ((void (*)(id, SEL, NSInteger))orig)(_self, sel, s);
                if ((int)s == 3 && [_self isKindOfClass:[NSURLSessionTask class]] && !objc_getAssociatedObject(_self, &kDoneKey)) {
                    objc_setAssociatedObject(_self, &kDoneKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                    NSURLSessionTask *t = _self;
                    NSURLRequest *r = t.currentRequest ?: t.originalRequest;
                    TLOG(@"[task-done] %@ status=%ld err=%@ url=%@", r.HTTPMethod ?: @"?", statusOf(t.response), errStr(t.error), safeURL(r.URL));
                }
            });
            MSHookMessageEx(c, sel, rep, &orig);
            noteRep(rep);
        }
    }
}

static void hookTaskClasses(void) {
    NSURLSession *ses = [NSURLSession sharedSession];
    NSURL *u = [NSURL URLWithString:@"http://127.0.0.1/"];
    NSURLRequest *rq = [NSURLRequest requestWithURL:u];
    NSMutableArray *samples = [NSMutableArray array];
    id t;
    if ((t = [ses dataTaskWithRequest:rq])) [samples addObject:t];
    if ((t = [ses uploadTaskWithRequest:rq fromData:[NSData data]])) [samples addObject:t];
    if ((t = [ses downloadTaskWithRequest:rq])) [samples addObject:t];
    NSMutableArray *chain = [NSMutableArray array];
    for (id sample in samples) {
        for (Class c = object_getClass(sample); c && c != [NSObject class]; c = class_getSuperclass(c)) {
            if (![chain containsObject:c]) [chain addObject:c];
        }
    }
    // Base classes first, so a subclass that calls super does not double-log (the associated-object flags also guard this).
    for (Class c in [chain reverseObjectEnumerator]) {
        TLOG(@"[hook] task class %s", class_getName(c));
        hookTaskClass(c);
    }
}

#pragma mark - App-level breadcrumbs (errors, screens, alerts, notifications, class names)

static BOOL interestingDomain(NSString *d) {
    if (!d.length) return NO;
    for (NSString *p in @[@"NS", @"kCF", @"com.apple", @"WK", @"_NS", @"AV", @"CK", @"SK"]) {
        if ([d hasPrefix:p]) return NO;
    }
    return YES;
}

static BOOL interestingNotification(NSString *n) {
    if (!n.length) return NO;
    for (NSString *p in @[@"UI", @"NS", @"_", @"AV", @"CA", @"WK", @"CF", @"com.apple", @"AX"]) {
        if ([n hasPrefix:p]) return NO;
    }
    NSString *lo = n.lowercaseString;
    for (NSString *k in @[@"auth", @"login", @"onboard", @"account", @"guest", @"signin", @"session", @"token", @"metric", @"instrument", @"flow", @"user"]) {
        if ([lo containsString:k]) return YES;
    }
    return NO;
}

static void dumpInterestingClasses(void) {
    NSArray *keys = @[@"auth", @"login", @"onboard", @"guest", @"signin", @"instrument", @"metric", @"xauth", @"account"];
    unsigned int ic = 0;
    const char **imgs = objc_copyImageNames(&ic);
    int shown = 0;
    unsigned int scanned = 0;
    for (unsigned int i = 0; i < ic; i++) {
        if (!strstr(imgs[i], ".app/")) continue;
        unsigned int n = 0;
        const char **names = objc_copyClassNamesForImage(imgs[i], &n);
        scanned += n;
        for (unsigned int j = 0; j < n && shown < 300; j++) {
            NSString *nm = [NSString stringWithUTF8String:names[j]];
            NSString *lo = nm.lowercaseString;
            for (NSString *k in keys) {
                if ([lo containsString:k]) { TLOG(@"[class] %@", nm); shown++; break; }
            }
        }
        free(names);
    }
    free(imgs);
    TLOG(@"[classes] scanned %u app classes, listed %d", scanned, shown);
}

static void dumpSelectors(NSString *className) {
    Class c = NSClassFromString(className);
    if (!c) { TLOG(@"[selectors] %@ : class not found", className); return; }
    NSArray *keys = @[@"enqueue", @"start", @"cancel", @"fail", @"error", @"complet", @"valid", @"auth", @"login", @"sign", @"submit", @"token", @"begin", @"finish", @"state", @"request"];
    int shown = 0;
    for (int pass = 0; pass < 2; pass++) {
        Class k = pass ? object_getClass(c) : c;
        unsigned int n = 0;
        Method *ms = class_copyMethodList(k, &n);
        for (unsigned int i = 0; i < n && shown < 70; i++) {
            NSString *sel = NSStringFromSelector(method_getName(ms[i]));
            NSString *lo = sel.lowercaseString;
            for (NSString *key in keys) {
                if ([lo containsString:key]) { TLOG(@"[selector] %c[%@ %@]", pass ? '+' : '-', className, sel); shown++; break; }
            }
        }
        free(ms);
    }
}

static NSString *describeTNLOp(id op) {
    NSMutableArray *parts = [NSMutableArray array];
    @try {
        id req = [op valueForKey:@"originalRequest"];
        id url = [req valueForKey:@"URL"];
        if ([url isKindOfClass:[NSURL class]]) [parts addObject:[NSString stringWithFormat:@"url=%@", safeURL(url)]];
        else if (req) [parts addObject:[NSString stringWithFormat:@"request=%@", NSStringFromClass([req class])]];
    } @catch (NSException *e) { [parts addObject:@"(no originalRequest)"]; }
    @try {
        id st = [op valueForKey:@"state"];
        if (st) [parts addObject:[NSString stringWithFormat:@"state=%@", st]];
    } @catch (NSException *e) {}
    return [parts componentsJoinedByString:@" "];
}

static void hookTNL(void) {
    Class q = NSClassFromString(@"TNLRequestOperationQueue");
    SEL sel = NSSelectorFromString(@"enqueueRequestOperation:");
    if (!canHook(q, sel)) { TLOG(@"[hook] TNL enqueueRequestOperation: not found"); return; }
    __block IMP orig = NULL;
    IMP rep = imp_implementationWithBlock(^(id _self, id op) {
        TLOG(@"[tnl-enqueue] %@ %@", NSStringFromClass([op class]), describeTNLOp(op));
        if (orig) ((void (*)(id, SEL, id))orig)(_self, sel, op);
    });
    MSHookMessageEx(q, sel, rep, &orig);
    noteRep(rep);
    TLOG(@"[hook] TNL enqueueRequestOperation: hooked");
}

%hook NSError

- (instancetype)initWithDomain:(NSString *)domain code:(NSInteger)code userInfo:(NSDictionary *)dict {
    if (interestingDomain(domain)) {
        NSString *desc = dict[NSLocalizedDescriptionKey];
        if (![desc isKindOfClass:[NSString class]]) desc = @"-";
        if (desc.length > 120) desc = [desc substringToIndex:120];
        NSMutableArray *extra = [NSMutableArray array];
        for (id k in dict) {
            id v = dict[k];
            if ([k isKindOfClass:[NSString class]] && [v isKindOfClass:[NSString class]] && ![k isEqualToString:NSLocalizedDescriptionKey]
                && [(NSString *)v length] < 100 && extra.count < 5) {
                [extra addObject:[NSString stringWithFormat:@"%@=%@", k, v]];
            }
        }
        TLOG(@"[error-created] domain=%@ code=%ld desc=%@ keys=%@ values=[%@]", domain, (long)code, desc,
             [[dict allKeys] componentsJoinedByString:@","], [extra componentsJoinedByString:@"; "]);
    }
    return %orig;
}

%end

%hook UIViewController

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *cn = NSStringFromClass([self class]);
    if ([self isKindOfClass:[UIAlertController class]]) {
        UIAlertController *a = (UIAlertController *)self;
        TLOG(@"[alert] title=%@ message=%@", a.title, a.message);
    } else if (![cn hasPrefix:@"UI"] && ![cn hasPrefix:@"_UI"]) {
        TLOG(@"[vc] appeared %@ title=%@", cn, self.title);
    }
}

%end

%hook UIAlertView

- (void)show {
    TLOG(@"[alert] (UIAlertView) title=%@ message=%@", [self valueForKey:@"title"], [self valueForKey:@"message"]);
    %orig;
}

%end

%hook NSNotificationCenter

- (void)postNotificationName:(NSString *)name object:(id)obj userInfo:(NSDictionary *)info {
    if (interestingNotification(name)) TLOG(@"[notify] %@ from %@", name, NSStringFromClass([obj class]));
    %orig;
}

- (void)postNotification:(NSNotification *)n {
    if (interestingNotification(n.name)) TLOG(@"[notify] %@ from %@", n.name, NSStringFromClass([n.object class]));
    %orig;
}

%end

#pragma mark - Auth / TNL tracing (log-only hooks that forward every argument unchanged)

typedef void (^TLEntryLogger)(id self, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f);

static id objAt(uintptr_t v) { return v ? (__bridge id)(void *)v : nil; }

static NSString *urlOfRequest(id req) {
    if (!req) return @"(nil)";
    @try {
        id url = [req valueForKey:@"URL"];
        if ([url isKindOfClass:[NSURL class]]) return safeURL(url);
    } @catch (NSException *ex) {}
    return [NSString stringWithFormat:@"(%@)", NSStringFromClass([req class])];
}

static NSString *lenOf(id o) {
    if (!o) return @"nil";
    if ([o respondsToSelector:@selector(length)]) return [NSString stringWithFormat:@"%@ len=%lu", NSStringFromClass([o class]), (unsigned long)[(NSString *)o length]];
    return NSStringFromClass([o class]);
}

// Hooks a method (instance method of c; pass the metaclass for class methods) and calls `logger` before forwarding.
static void hookEntry(Class c, NSString *selName, TLEntryLogger logger) {
    SEL sel = NSSelectorFromString(selName);
    if (!canHook(c, sel)) { TLOG(@"[hook] missing %s %@", c ? class_getName(c) : "(nil class)", selName); return; }
    __block IMP orig = NULL;
    IMP rep = imp_implementationWithBlock(^uintptr_t(id _self, uintptr_t a, uintptr_t b, uintptr_t cc, uintptr_t d, uintptr_t e, uintptr_t f) {
        @try { logger(_self, a, b, cc, d, e, f); } @catch (NSException *ex) {}
        if (!orig) return 0;
        return ((uintptr_t (*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))orig)(_self, sel, a, b, cc, d, e, f);
    });
    MSHookMessageEx(c, sel, rep, &orig);
    noteRep(rep);
}

static void hookAuthAndTNL(void) {
    Class gm = NSClassFromString(@"TFSAuthGuestAuthManager");
    hookEntry(gm, @"signRequest:completion:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[auth] guest signRequest %@", urlOfRequest(objAt(a)));
    });
    hookEntry(gm, @"retrieveGuestAuthTokensWithCompletionBlock:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[auth] retrieveGuestAuthTokens");
    });
    hookEntry(gm, @"_acquireGuestToken", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[auth] _acquireGuestToken");
    });
    hookEntry(gm, @"_acquireTokensWithAppToken:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[auth] _acquireTokensWithAppToken appToken=%@", lenOf(objAt(a)));
    });
    hookEntry(gm, @"_acquireTokensUseKeychain:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[auth] _acquireTokensUseKeychain use=%d", (int)(a & 0xFF));
    });
    hookEntry(gm, @"_tokenAcquisitionDidCompleteWithSuccess:error:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        id err = objAt(b);
        TLOG(@"[auth] _tokenAcquisitionDidComplete success=%d err=%@", (int)(a & 0xFF), [err isKindOfClass:[NSError class]] ? errStr(err) : @"none");
    });
    hookEntry(gm, @"_handleTokenAcquisitionServerCallFailure:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        id o = objAt(a);
        TLOG(@"[auth] _handleTokenAcquisitionServerCallFailure arg=%@ %@", o ? NSStringFromClass([o class]) : @"nil", [o isKindOfClass:[NSError class]] ? errStr(o) : @"");
    });
    hookEntry(gm, @"setAuthState:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[auth] guest authState -> %ld", (long)a);
    });
    hookEntry(gm, @"setGuestToken:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[auth] setGuestToken %@", lenOf(objAt(a)));
    });
    hookEntry(gm, @"_isInvalidAppTokenFromHTTPStatus:apiErrorCode:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[auth] _isInvalidAppToken httpStatus=%ld apiErrorCode=%ld", (long)a, (long)b);
    });
    hookEntry(gm, @"handleGuestAuthRequestResponse:completion:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        id o = objAt(a);
        TLOG(@"[auth] handleGuestAuthRequestResponse %@", o ? NSStringFromClass([o class]) : @"nil");
    });

    // Sign-in manager (identifiers and passwords are never logged).
    Class sm = NSClassFromString(@"T1SignInManager");
    hookEntry(sm, @"addUser:password:oneFactorAuthorizationRequestType:uiMetrics:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[signin] addUser called type=%ld uiMetrics=%@", (long)c, lenOf(objAt(d)));
    });
    hookEntry(sm, @"_requestAccessTokensWithIdentifier:password:uiMetrics:oneFactorAuthorizationRequestType:responseBlock:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[signin] _requestAccessTokens uiMetrics=%@ type=%ld", lenOf(objAt(c)), (long)d);
    });
    if (sm) {
        hookEntry(object_getClass(sm), @"_guestAuthCreateAuthenticatedRequestWithIdentifier:password:simCountryCode:uiMetrics:oneFactorAuthorizationRequestType:responseBlock:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
            TLOG(@"[signin] _guestAuthCreateAuthenticatedRequest uiMetrics=%@ type=%ld", lenOf(objAt(d)), (long)e);
        });
    }
    hookEntry(sm, @"_mappedErrorFromAPIResponseModelParseError:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        id err = objAt(a);
        TLOG(@"[signin] _mappedErrorFromAPIResponseModelParseError %@", [err isKindOfClass:[NSError class]] ? errStr(err) : @"nil");
    });

    // TNL operation lifecycle.
    Class op = NSClassFromString(@"TNLRequestOperation");
    hookEntry(op, @"_tnl_setState:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[tnl-state] -> %ld %@", (long)a, describeTNLOp(s));
    });
    hookEntry(op, @"setHydratedRequest:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        TLOG(@"[tnl-hydrated] %@", describeTNLOp(s));
    });
    hookEntry(op, @"cancelWithSource:underlyingError:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        id src = objAt(a); id err = objAt(b);
        NSString *sd = src ? [NSString stringWithFormat:@"%@", src] : @"nil";
        if (sd.length > 80) sd = [sd substringToIndex:80];
        TLOG(@"[tnl-cancel] source=%@ underlying=%@ %@", sd, [err isKindOfClass:[NSError class]] ? errStr(err) : @"none", describeTNLOp(s));
    });
    Class q = NSClassFromString(@"TNLRequestOperationQueue");
    hookEntry(q, @"operation:didCompleteWithResponse:", ^(id s, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) {
        id o = objAt(a);
        id err = nil;
        @try { err = [o valueForKey:@"error"]; } @catch (NSException *ex) {}
        TLOG(@"[tnl-complete] error=%@ %@", [err isKindOfClass:[NSError class]] ? errStr(err) : @"none", describeTNLOp(o));
    });
}

#pragma mark - Feature-switch discovery

static BOOL fsKeyInteresting(NSString *k) {
    NSString *lo = k.lowercaseString;
    for (NSString *w in @[@"sign", @"login", @"log_in", @"onboard", @"flow", @"adaptive", @"xauth", @"welcome", @"signup", @"auth", @"wizard"]) {
        if ([lo containsString:w]) return YES;
    }
    return NO;
}

static BOOL simpleEncoding(const char *t) {
    if (!t) return NO;
    switch (t[0]) {
        case '@': case 'B': case 'c': case 'C': case 'i': case 'I': case 's': case 'S':
        case 'l': case 'L': case 'q': case 'Q': case 'v': case '#': case ':': return YES;
        default: return NO;
    }
}

// Logs calls to a feature-switch style method (only when a string argument looks login related) and forwards unchanged.
static BOOL hookFeatureMethod(Class c, Method m) {
    SEL sel = method_getName(m);
    NSString *name = NSStringFromSelector(sel);
    if ([name hasPrefix:@"init"] || [name isEqualToString:@"dealloc"] || [name hasPrefix:@"."]) return NO;
    unsigned int nargs = method_getNumberOfArguments(m);
    if (nargs < 3 || nargs > 5) return NO;
    char *rt = method_copyReturnType(m);
    char retc = rt ? rt[0] : 0;
    BOOL okRet = rt && simpleEncoding(rt) && retc != '#' && retc != ':';
    if (rt) free(rt);
    if (!okRet) return NO;
    NSMutableString *enc = [NSMutableString string];
    for (unsigned int i = 2; i < nargs; i++) {
        char *at = method_copyArgumentType(m, i);
        BOOL ok = simpleEncoding(at);
        [enc appendFormat:@"%c", at ? at[0] : '?'];
        if (at) free(at);
        if (!ok) return NO;
    }
    if ([enc rangeOfString:@"@"].location == NSNotFound) return NO;
    if (!canHook(c, sel)) return NO;
    NSString *tag = [NSString stringWithUTF8String:class_getName(c)];
    __block IMP orig = NULL;
    IMP rep = imp_implementationWithBlock(^uintptr_t(id _self, uintptr_t a, uintptr_t b, uintptr_t cc, uintptr_t d, uintptr_t e, uintptr_t f) {
        uintptr_t r = orig ? ((uintptr_t (*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))orig)(_self, sel, a, b, cc, d, e, f) : 0;
        @try {
            uintptr_t args[3] = {a, b, cc};
            NSMutableArray *strs = [NSMutableArray array];
            BOOL interesting = NO;
            for (NSUInteger i = 0; i < enc.length && i < 3; i++) {
                if ([enc characterAtIndex:i] == '@' && args[i]) {
                    id o = objAt(args[i]);
                    if ([o isKindOfClass:[NSString class]] && [(NSString *)o length] < 100) {
                        [strs addObject:o];
                        if (fsKeyInteresting(o)) interesting = YES;
                    }
                }
            }
            if (interesting) {
                NSString *res;
                if (retc == 'B' || retc == 'c' || retc == 'C') res = [NSString stringWithFormat:@"%d", (int)(r & 0xFF)];
                else if (retc == 'v') res = @"void";
                else if (retc == '@') {
                    id ro = objAt(r);
                    if ([ro isKindOfClass:[NSString class]] || [ro isKindOfClass:[NSNumber class]]) res = [NSString stringWithFormat:@"%@", ro];
                    else res = ro ? NSStringFromClass([ro class]) : @"nil";
                    if (res.length > 60) res = [res substringToIndex:60];
                } else res = [NSString stringWithFormat:@"%ld", (long)r];
                static NSMutableSet *seenFS; static dispatch_once_t onceFS;
                dispatch_once(&onceFS, ^{ seenFS = [NSMutableSet set]; });
                NSString *fk = [NSString stringWithFormat:@"%@|%@|%@", tag, name, [strs componentsJoinedByString:@"|"]];
                BOOL isNew;
                @synchronized (seenFS) { isNew = ![seenFS containsObject:fk]; if (isNew) [seenFS addObject:fk]; }
                if (isNew) TLOG(@"[fs] -[%@ %@] (%@) -> %@", tag, name, [strs componentsJoinedByString:@" | "], res);
            }
        } @catch (NSException *ex) {}
        return r;
    });
    MSHookMessageEx(c, sel, rep, &orig);
    noteRep(rep);
    return YES;
}

static void hookFeatureSwitchClasses(void) {
    unsigned int ic = 0;
    const char **imgs = objc_copyImageNames(&ic);
    NSMutableArray *found = [NSMutableArray array];
    for (unsigned int i = 0; i < ic; i++) {
        if (!strstr(imgs[i], ".app/")) continue;
        unsigned int n = 0;
        const char **names = objc_copyClassNamesForImage(imgs[i], &n);
        for (unsigned int j = 0; j < n; j++) {
            NSString *nm = [NSString stringWithUTF8String:names[j]];
            if ([nm.lowercaseString containsString:@"featureswitch"]) [found addObject:nm];
        }
        free(names);
    }
    free(imgs);
    int hooked = 0;
    for (NSString *nm in found) {
        Class c = NSClassFromString(nm);
        if (!c) continue;
        int perClass = 0;
        for (int pass = 0; pass < 2 && hooked < 400; pass++) {
            Class k = pass ? object_getClass(c) : c;
            unsigned int mc = 0;
            Method *ms = class_copyMethodList(k, &mc);
            for (unsigned int i = 0; i < mc && hooked < 400; i++) {
                if (hookFeatureMethod(k, ms[i])) { hooked++; perClass++; }
            }
            free(ms);
        }
        TLOG(@"[fs-class] %@ hooked=%d", nm, perClass);
    }
    TLOG(@"[fs] feature-switch classes found=%lu, methods hooked=%d", (unsigned long)found.count, hooked);
}

static void dumpSelectorsFiltered(NSString *className, NSArray *keys, int cap) {
    Class c = NSClassFromString(className);
    if (!c) { TLOG(@"[selectors] %@ : class not found", className); return; }
    int shown = 0;
    for (int pass = 0; pass < 2; pass++) {
        Class k = pass ? object_getClass(c) : c;
        unsigned int n = 0;
        Method *ms = class_copyMethodList(k, &n);
        for (unsigned int i = 0; i < n && shown < cap; i++) {
            NSString *sel = NSStringFromSelector(method_getName(ms[i]));
            BOOL match = (keys == nil);
            for (NSString *key in keys) { if ([sel.lowercaseString containsString:key]) { match = YES; break; } }
            if (match) { TLOG(@"[selector] %c[%@ %@]", pass ? '+' : '-', className, sel); shown++; }
        }
        free(ms);
    }
}

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
        hookTaskClasses();
        hookTNL();
        hookAuthAndTNL();
        hookFeatureSwitchClasses();

        %init;
    }
}
