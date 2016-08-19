/* Configure JSHint warnings, http://jshint.com/docs/options/, http://stackoverflow.com/questions/17535130/where-can-i-find-a-list-of-jshint-numeric-error-codes#17541721 *//* exported include */// jshint asi:true, browser:true, devel:true, eqeqeq:true, esnext:true, evil:true, node:true, strict:true, undef:true, -W100

/*
Alternative to ES6 modules to side-step their Node.js+Babel basterdization¹,
have something that works every where now,
multiple functions are supported as methods on a monolithic module object instead of complex import syntax,
and supports Github references in the default loader.

Each module file must contain a single top-level invocation of a function (which must not return a `Promise`) or a function;
and function level², instead of global, 'use strict'.

Usage is always analogous to default mode of ES6 modules but a syntax similar to `require`
in Node.js, yet returning a `Promise`:

  `const name = await include('file reference')` <-- contained within an `async` function
  `const name = yield include('file reference')` <-- contained within a generator function invoked with `asyncify()`

The default loader supports urls and Github references. The '.js' extension is appended if missing.
For urls, paths are relative to `window.location.pathname` on the browser;
otherwise this script's directory on Node.js.

Github references are of the format, 'github:account/repository/[path/]file[.js][#branch|#changeset]'.

For local files in Android WebView, remember to enable `getSettings().setAllowFileAccess()`³.
Presumably the meta tag form⁴ of Content Security Policy⁵ can be employed to restrict
the directory against XSS attacks⁶, but remember to enable 'unsafe-eval'⁷.
HTTP access control (CORS)⁸ is an inapplicable server whitelist.

¹ https://github.com/nodejs/node-eps/issues/13#issuecomment-222989505
² https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode#Strict_mode_for_scripts
  http://stackoverflow.com/questions/19910134/jshint-use-strict-issue#answer-19911738
³ http://stackoverflow.com/questions/23955050/xmlhttprequest-cannot-load-file-from-android-asset-folder-on-emulator#answer-24529063
⁴ http://www.html5rocks.com/en/tutorials/security/content-security-policy/#the-meta-tag
  https://w3c.github.io/webappsec-csp/#meta-element
  https://bugzilla.mozilla.org/show_bug.cgi?id=663570
⁵ https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
  http://caniuse.com/#feat=contentsecuritypolicy
  https://www.owasp.org/index.php/Content_Security_Policy
⁶ https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
⁷ https://www.w3.org/TR/CSP2/#directive-script-src
⁸ https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
*/
const include = (() => {
  'use strict'
  const url_pattern    = '((?:[^/]+/)*[^\.]+)(?:\.js)?', // ((?:[^/]+/)* optional 'path/' not captured, [^\.]+ 'file' not captured) captured, (?:\.js)? optional '.js' not captured
        url_re         = new RegExp(url_pattern),
        github         = new RegExp('github:([^/]+/[^/]+/)' + url_pattern + '(\#.+)?'), // ([^/]+/[^/]+/) capture 'account/repository/', (\#.+)? capture optional '#branch|changeset',
        is_node        = (new Function("return global !== undefined && this === global && Object.prototype.toString.call(global.process) === '[object process]'"))(), // create new Function() so `global` will refer to the global variable; only Node.js has a process variable that is of [[Class]] process
        dir            = is_node ? __dirname : window.location.pathname,
        not_ref        = 'Incorrect syntax for module reference',
        timeout        = 'Module loading timed out',
        cache          = new Map(),
        XMLHttpRequest = is_node ? require('xhr2') : XMLHttpRequest

  // Set default handling of uncaught rejected promises.
  function f(reason, promise) {
    console.log('Unhandled Rejection at: Promise', promise, 'reason:', reason)
    throw reason
  }
  if (is_node)
    process.on('unhandledRejection', f)                         // https://nodejs.org/api/process.html#process_event_unhandledrejection
  else
    window.addEventListener("unhandledrejection", f)            // http://stackoverflow.com/questions/28001722/how-to-catch-uncaught-exception-in-promise#answer-28004999

  return (ref/*:String*/) => {
    let a = ref.match(github)
    const url = a ? 'https://' + a[1] + 'blob/' + (a[3].length === 0 ? 'master/' : a[3].substr(1) + '/') + a[2] + '.js'
                  : (a = ref.match(url_re)) ? dir + '/' + a[1] + '.js'
                                            : null
    if (console.assert(url, not_ref)) {
      const cached = cache.get(url)
      if (cached && cached instanceof Promise)                  // circular dependency?
        return cached
      const promise = new Promise((resolve, reject) => {        // inputs callback functions to resolve and reject the returned `Promise`
        if (cached)
          resolve(cached)
        else {
          cache.set(url, promise)                               // support circular dependencies
          let xhr = new XMLHttpRequest()
          xhr.timeout = () => reject(new Error(timeout))
          xhr.onreadystatechange = () => {
            if (xhr.readyState === XMLHttpRequest.DONE) {
              if (xhr.status === 200) {
                const o = eval('(' + xhr.responseText + ')')    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#eval_as_a_string_defining_function_requires_(_and_)_as_prefix_and_suffix
                cache.set(url, o)
                resolve(o)
              }
              else
                reject(new Error(xhr.statusText))
            }
          }
          xhr.open('GET', url, /*asynchronous*/true)
          xhr.timeout = 10000                                 // 10 seconds
          xhr.send(/*no HTTP request body*/null)
        }
      })
      return promise
    }
    else
      throw new SyntaxError(not_ref)
  }
})()