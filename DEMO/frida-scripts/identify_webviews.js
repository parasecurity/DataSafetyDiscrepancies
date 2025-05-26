Java.performNow(function(){ 
    // Java.deoptimizeEverything();

    var webView = Java.use("android.webkit.WebView");
    var webSettings = Java.use("android.webkit.WebSettings");
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    var WebChromeClient = Java.use("android.webkit.WebChromeClient");
    var Thread = Java.use('java.lang.Thread');
    var Log = Java.use("android.util.Log"); 

    let WebViewsDict= new Map();
    Log.d("UI-LoadedWebviews","Init");

    var debug_flag=0;
    function functionInjectScriptWebView(tmp_webView){
        
        if (debug_flag==1){console.log("+++++++++++++INJECTING JS TO WEBVIEW++++++++++++++++"+tmp_webView.getUrl() +" " + tmp_webView.hashCode() +" " + tmp_webView.getSettings().getJavaScriptEnabled());} 
        
        const Java_String = Java.use('java.lang.String');        
        var myScript = "(function() " +
                        "{  "+
                        "var perfData = window.performance.timing;" +
                        "var loadTime = perfData.loadEventEnd - perfData.navigationStart;" +
                        "if (loadTime>=0) {" +
                        "console.log(\"diamant["+ tmp_webView.getUrl() +"]<"+ tmp_webView.hashCode() + "> Page load time: \" + loadTime + \"ms (\" + loadTime/1000 + \"s)\"); " +        
                        // "console.log(\"diamant[]<"+ tmp_webView.hashCode() + "> Page load time: \" + loadTime + \"ms (\" + loadTime/1000 + \"s)\"); " +        

                        "}" +
                        "} )();"

        tmp_webView.evaluateJavascript(Java_String.$new(myScript),null);

        
            
    }


    function printMap(){
        if (debug_flag==0){return;} 
        console.log("+++++++++++++++++++++++++++++");
        for (const [key, value] of WebViewsDict.entries()) {
            console.log(key + ": " + value);
        }
        console.log("+++++++++++++++++++++++++++++");
    }

    function printToLogcat()
    {
        var valueToPrint=checkWebViewsDict();
        console.log("++++++++++++valueToPrint: UI-LoadedWebviews", valueToPrint.toString());
        Log.d("UI-LoadedWebviews", valueToPrint.toString());
        
    }
    function checkWebViewsDict()
    {
        var allLoaded=1;
        for (const [key, value] of WebViewsDict.entries()){
            if (value==0)
            {
                allLoaded=0;
            }
            console.log(key, value)
            if (debug_flag==1){Log.d("UI-Webviews", key+" "+value);} 
            
        }
        return allLoaded;
    }
    function addWebView(tmp,url){
        //we do not need the if condition (debugging purposes). set()will add new item or overwrite value if exists 
        if (url.startsWith("javascript:")==false)
            if (WebViewsDict.has(tmp.hashCode().toString()))
            {
                //webview not in Map --> add
                WebViewsDict.delete(tmp.hashCode().toString());
                WebViewsDict.set(tmp.hashCode().toString(),0); 
            }
            else
            {
                //webview in Map --> overwite value
                WebViewsDict.set(tmp.hashCode().toString(),0);
            }
    printToLogcat();
    }


    function webviewRenderComplete(tmp){
            WebViewsDict.set(tmp,1)
            printToLogcat(); 
    }   
        
    function webviewRenderCompleteOnDestroy(tmp){
        console.log(WebViewsDict.has(tmp), tmp)
        if (WebViewsDict.has(tmp)){
            WebViewsDict.delete(tmp);
            WebViewsDict.set(tmp,1)
            printToLogcat(); 
        }
    }

    var Color = {
      RESET: "\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", Green: "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01",
      Light: {Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", Green: "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11"
      }
    };

    var colorLog = function (input, kwargs) {
      kwargs = kwargs || {};
      var logLevel = kwargs['l'] || 'log', colorPrefix = '\x1b[3', colorSuffix = 'm';
      if (typeof input === 'object')
          input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
      if (kwargs['c'])
          input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
      console[logLevel](input);
    };

    let overloadCount_1691770814 = webView['$init'].overloads.length;
      colorLog('\\nTracing ' +'$init' + ' [' + overloadCount_1691770814 + 'overload(s)]',{ c: Color.Green });

        for (let i = 0; i < overloadCount_1691770814; i++) {
          webView['$init'].overloads[i].implementation = function() {
          colorLog('[i] Entering Webview.' +'$init',{ c: Color.Green });
            this.setWebContentsDebuggingEnabled(true);
            console.log('Enabling setWebContentsDebuggingEnabled');
            if (arguments.length) console.log();
            
            let retval = this['$init'].apply(this, arguments);


            console.log('Enabling setJavaScriptEnabled');
            this.getSettings().setJavaScriptEnabled(true);

            // init webChrome/WebView clients

            colorLog('[i] Webview getWebViewClient' +this.getWebViewClient() ,{ c: Color.Green });
            

            try{
                this.setWebViewClient(WebViewClient.$new());
                this.setWebChromeClient(WebChromeClient.$new());
            }
            catch(e){

            }

            // var myMessage = Java.use('android.webkit.ConsoleMessage');
            // WebChromeClient.onConsoleMessage(myMessage);

            colorLog('[i] exiting Webview.' + '$init',{ c: Color.Green });

            getstacktrace("$init()");

            return retval;
      }
    }

    function highlight(tag, flag){
    if(flag)
        colorLog(tag + flag,{c:Color.Red});
    else 
        console.log(tag+flag);

    }

    function dumpWebview(wv){
        colorLog('[i] ---------------- Dumping webview settings -------------------:',{c:Color.Yellow});
        colorLog('=====> Class Name: '+wv.$className,{c:Color.Gray});
        colorLog('=====> WebView Client: '+wv.getWebViewClient()+ " " +wv.hashCode(),{c:Color.Gray});
        highlight('     Allows Content Access: ',wv.getSettings().getAllowContentAccess());
        highlight('     Allows Javascript execution: ',wv.getSettings().getJavaScriptEnabled());
        highlight('     Allows File Access: ',wv.getSettings().getAllowFileAccess());
        highlight('     Allows File Access From File URLs: ',wv.getSettings().getAllowFileAccessFromFileURLs());
        highlight('     Allows Universal Access from File URLs: ',wv.getSettings().getAllowUniversalAccessFromFileURLs());
        colorLog('[i] ---------------- Dumping webview settings EOF ---------------].',{c:Color.Yellow});

    }

    function getstacktrace(func_name){
        if (debug_flag==1){return;} 
        var threadinstance = Thread.$new();
        var stack = threadinstance.currentThread().getStackTrace()
        var full_call_stack = "";
        for(var i = 0; i < stack.length; i++){
            full_call_stack += stack[i].toString() + "\n";
        }
        colorLog("\n---------------- Stack Trace {"+func_name+"} ----------------", {c:Color.Gray})
        colorLog(full_call_stack, {c:Color.Gray})
        colorLog("----------------------- Stack Trace End -----------------------", {c:Color.Gray})
    }

    webView.getUrl.implementation = function(){
        dumpWebview(this);
        colorLog('[i] Current Loaded url:' + this.getUrl(),{c:Color.Blue});
        return this.getUrl();
    }
    webSettings.setJavaScriptEnabled.implementation = function(allow){
        console.log('[!] Java Script Enabled:' + allow);
        return this.setJavaScriptEnabled(allow);

    }

    webView.evaluateJavascript.implementation = function(script, resultCallback){
        colorLog('WebView Client: '+this.getWebViewClient()+" "+this.hashCode(),{c:Color.Blue});
        colorLog('[i] evaluateJavascript called with the following script: '+script,{c:Color.White});
        this.evaluateJavascript(script,resultCallback);
    }

    webView.getOriginalUrl.implementation = function(){
        console.log('[i] Original URL: ' + this.getOriginalUrl());
        return this.getOriginalUrl();
    }

    webView.addJavascriptInterface.implementation = function(object, name){
        colorLog('[i] Javascript interface detected:' + object.$className + ' instatiated as: ' + name,{c:Color.Red});
        this.addJavascriptInterface(object,name);
    }



    webView.loadData.implementation = function(data, mimeType, encoding){
        dumpWebview(this);
        console.log('[i] Load data called with the following parameters {'+this.hashCode()+'}:\\n' + 'Data:' + data + '\\nMime type: '+mimeType+'\\nEncoding: '+ encoding);
        // addWebView(this,"mimeType");printMap();

        getstacktrace("loadData(String, String, String)");

        this.loadData(data,mimeType,encoding);
        
    }

    webView.loadDataWithBaseURL.implementation = function(baseUrl,  data,  mimeType,  encoding,  historyUrl){
        dumpWebview(this);
        console.log('[i] loadDataWithBaseURL call detected, having the following parameters {'+this.hashCode()+'}:'+
        // '\\nBaseUrl: ' + baseUrl);
        '\\nBaseUrl: ' + baseUrl +
        '\\nData: ' + data+
        '\\nmimeType: ' + mimeType+
        '\\nhistory URL' + historyUrl);
        // addWebView(this,baseUrl);printMap();

        getstacktrace("loadDataWithBaseURL(String, String, String, String, String)");

        this.loadDataWithBaseURL(baseUrl,data,mimeType,encoding,historyUrl);
        
    }

    webView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url,additionalHttpHeaders){
        dumpWebview(this);
        var iterator = additionalHttpHeaders.entrySet().iterator();
        console.log('=======Aditional headers contents:=========');
        while(iterator.hasNext()) {
            var entry = Java.cast(iterator.next(), Java.use('java.util.Map$Entry'));
            console.log(entry.getKey() + ': ' + entry.getValue());
        }
        console.log('[i] Loading URL {'+this.hashCode()+'}: ' + url);
        // addWebView(this,url);printMap();
        console.log('===========================================');

        getstacktrace("loadUrl(String, Map)")
        

        this.loadUrl(url,additionalHttpHeaders);
    }

    webView.loadUrl.overload('java.lang.String').implementation = function(url){
        dumpWebview(this);
        console.log('[i] Loading URL {'+this.hashCode()+'}:' + url);
        colorLog('webView: ' +this + "webView.$className: " + this.$className );
        // addWebView(this,url);printMap();
        getstacktrace("loadUrl(String)");

        this.loadUrl(url);
        
    }

    webView.reload.overload().implementation = function(){
        dumpWebview(this);
        console.log('[i] Reloading URL {'+this.hashCode()+'}:' + this.getUrl());
        colorLog('webView: ' +this + "webView.$className: " + this.$className );
        // addWebView(this,this.getUrl());printMap();
        getstacktrace("reload()");

        this.reload();
        
    }
    
    webView.destroy.implementation = function (){
        console.log('[i] Destroy {'+this.hashCode()+'}');
        webviewRenderCompleteOnDestroy(this.hashCode().toString())
        console.log("+++++++++++++++++++++++++++++");
        for (const [key, value] of WebViewsDict.entries()) {
            console.log(key + ": " + value);
        }
        console.log("+++++++++++++++++++++++++++++");
    }
    webView.disableWebView.implementation = function (){
        console.log('[i] disableWebView() {'+this.hashCode()+'}');
        webviewRenderCompleteOnDestroy(this.hashCode().toString())
        console.log("+++++++++++++++++++++++++++++");
        for (const [key, value] of WebViewsDict.entries()) {
            console.log(key + ": " + value);
        }
        console.log("+++++++++++++++++++++++++++++");
    }

    webView.setWebChromeClient.implementation = function(client){
        colorLog('WebChromeClient$className: ' + client.$className );
        colorLog('WebChromeClient: ' + client );
        WebChromeClient.onConsoleMessage.overload('android.webkit.ConsoleMessage').implementation = function(consoleMessage){
            colorLog('[i] onConsoleMessage:' + consoleMessage.message(),{c:Color.Yellow});
            var Log = Java.use("android.util.Log");
            var TAG_L = "[FRIDA-diamant]";
            Log.d(TAG_L, consoleMessage.message());

            if (consoleMessage.message().includes("diamant["))
            {
                var tmp_hashcode = consoleMessage.message().split(/[<>]/)[1];
                webviewRenderComplete(tmp_hashcode);printMap();
            }
            else
            {
                colorLog('[i] onConsoleMessage:' + consoleMessage.message(),{c:Color.Yellow});
            }
            
            return true;
        }
        WebChromeClient.onConsoleMessage.overload('java.lang.String', 'int', 'java.lang.String').implementation = function(consoleMessage){
            colorLog('[i] onConsoleMessage:' + consoleMessage.message(),{c:Color.Yellow});
            var Log = Java.use("android.util.Log");
            var TAG_L = "[FRIDA-diamant]";
            Log.d(TAG_L, consoleMessage.message());

            if (consoleMessage.message().includes("diamant["))
            {
                var tmp_hashcode = consoleMessage.message().split(/[<>]/)[1];
                webviewRenderComplete(tmp_hashcode);printMap();
            }
            else
            {
                colorLog('[i] onConsoleMessage:' + consoleMessage.message(),{c:Color.Yellow});
            }
            
            return true;
        }
        WebChromeClient.onProgressChanged.implementation = function(webView, newProgress){
            console.log('[i] onProgressChanged:' + webView.hashCode() + webView.getUrl());
            colorLog('webView: ' +webView + "webView.$className: " + webView.$className + webView.hashCode() );
            if (newProgress >= 100) 
            {
                functionInjectScriptWebView(webView);
                
            }
            this.onProgressChanged(webView, newProgress)

            var retval = this.onProgressChanged.apply(this, arguments);
            return retval;


        }
        //this.setWebChromeClient(client);
        var retval = this.setWebChromeClient.apply(this, arguments)
        return retval;  
    }

    webView.setWebViewClient.implementation = function(client){
        colorLog('setWebViewClient-WebviewClient$className:' + client.$className);
        colorLog('setWebViewClient-WebviewClient: ' + client );
        // const result1 = this.setWebViewClient.overload("android.webkit.WebViewClient").call(this,client);

        WebViewClient.onPageStarted.implementation = function(webView, url, favicon) {
            
            if (webView.getUrl().toString().includes("https://ws.tapjoyads.com/events/proxy"))
            {
                //our injected Javascript can not print to console.log for this url/script
                colorLog('[i] onPageStarted URL not adding WebView to WebViewsDict:' + url,{c:Color.Purple} + webView.hashCode() + webView.getUrl() );  
            }
            else
            {

                colorLog('[i] onPageStarted URL:' + url,{c:Color.Purple} + webView.hashCode() + webView.getUrl() );
                addWebView(webView,webView.getUrl());printMap();
            }
            
            //this.onPageFinished.overload("android.webkit.WebView","java.lang.String").call(this, webView, url);//to exw den to exw einai to idio
            //this.onPageFinished(webView,url);//to exw den to exw einai to idio
            


            var retval = this.onPageStarted.apply(this, arguments);
            return retval;

        }


        // onPageFinished is called twice --> https://issuetracker.google.com/issues/36983315
        WebViewClient.onPageFinished.implementation = function(webView, url) {
                
            colorLog('[i] onPageFinished URL:' + url,{c:Color.Purple} + webView.hashCode() + webView.getUrl() );
            colorLog('webView: ' +webView + "webView.$className: " + webView.$className + webView.hashCode() );

            

            functionInjectScriptWebView(webView);
            
            //this.onPageFinished.overload("android.webkit.WebView","java.lang.String").call(this, webView, url);//to exw den to exw einai to idio
            //this.onPageFinished(webView,url);//to exw den to exw einai to idio
            


            var retval = this.onPageFinished.apply(this, arguments);
            return retval;

        }

        // WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function(webView, request, error) {
                
        //     colorLog('[i] onReceivedError URL:' + webView.getUrl(),{c:Color.Purple} + webView.hashCode() + webView.getUrl() );
        //     colorLog('webView: ' +webView + "webView.$className: " + webView.$className + webView.hashCode() );

            

        //     functionInjectScriptWebView(webView);
        //     webviewRenderComplete(webView.hashCode().toString());printMap();
            
           

        //     var retval = this.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').apply(this, arguments);
        //     return retval;

        // }

        // WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(webView, request, error) {
                
        //     colorLog('[i] onReceivedError URL:' + webView.getUrl(),{c:Color.Purple} + webView.hashCode() + webView.getUrl() );
        //     colorLog('webView: ' +webView + "webView.$className: " + webView.$className + webView.hashCode() );

            

        //     functionInjectScriptWebView(webView);
        //     webviewRenderComplete(webView.hashCode().toString());printMap();
            

        //     var retval = this.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').apply(this, arguments);
        //     return retval;

        // }
        // WebViewClient.onReceivedHttpError.implementation = function(webView, request, errorResponse) {
                
        //     colorLog('[i] onReceivedHttpError URL:' + webView.getUrl(),{c:Color.Purple} + webView.hashCode() + webView.getUrl() );
        //     colorLog('webView: ' +webView + "webView.$className: " + webView.$className + webView.hashCode() );

            

        //     functionInjectScriptWebView(webView);
        //     webviewRenderComplete(webView.hashCode());printMap();
            
        //     //this.onPageFinished.overload("android.webkit.WebView","java.lang.String").call(this, webView, url);//to exw den to exw einai to idio
        //     //this.onPageFinished(webView,url);//to exw den to exw einai to idio
            


        //     var retval = this.onReceivedError.apply(this, arguments);
        //     return retval;

        // }

        // return;
        // const lol = this.setWebViewClient.overload("android.webkit.WebViewClient").call(this,client);

        this.setWebViewClient(client);// an to balw trexei h kanonikh onPageFinished pou sto app mou exei to evalJS, an den to balw trexei i dikia mou

        
        var retval = this.setWebViewClient.apply(this, arguments);
        return retval;  
    }





});