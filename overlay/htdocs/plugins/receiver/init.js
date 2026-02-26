(function () {
    if (window.__dsdfmeReceiverInitLoaded) {
        return;
    }
    window.__dsdfmeReceiverInitLoaded = true;

    console.log("DSDFME init loaded");

    function showWatermark() {
        if (window.__dsdfmeWatermarkShown) {
            return;
        }
        window.__dsdfmeWatermarkShown = true;

        function render() {
            var mark = document.createElement("div");
            mark.id = "dsdfme-loaded-watermark";
            mark.textContent = "DSDFME LOADED";
            mark.style.position = "fixed";
            mark.style.right = "10px";
            mark.style.bottom = "10px";
            mark.style.zIndex = "99999";
            mark.style.padding = "4px 8px";
            mark.style.borderRadius = "4px";
            mark.style.background = "rgba(0, 0, 0, 0.75)";
            mark.style.color = "#8dff98";
            mark.style.font = "600 12px/1.2 monospace";
            mark.style.pointerEvents = "none";
            document.body.appendChild(mark);

            setTimeout(function () {
                if (mark.parentNode) {
                    mark.parentNode.removeChild(mark);
                }
            }, 2000);
        }

        if (document.body) {
            render();
        } else {
            document.addEventListener("DOMContentLoaded", render, { once: true });
        }
    }

    function addCss(href) {
        if (document.querySelector('link[data-dsdfme-auto=\"css\"]')) {
            return;
        }
        var link = document.createElement("link");
        link.rel = "stylesheet";
        link.type = "text/css";
        link.href = href;
        link.setAttribute("data-dsdfme-auto", "css");
        document.head.appendChild(link);
    }

    function addScript(src, onload) {
        var existing = document.querySelector('script[data-dsdfme-auto=\"js\"]');
        if (existing) {
            if (typeof onload === "function") {
                if (typeof window.DSDFME_AUTO_INIT === "function") {
                    onload();
                } else {
                    existing.addEventListener("load", onload, { once: true });
                }
            }
            return;
        }

        var script = document.createElement("script");
        script.src = src;
        script.async = false;
        script.setAttribute("data-dsdfme-auto", "js");
        if (typeof onload === "function") {
            script.onload = onload;
        }
        document.head.appendChild(script);
    }

    function bootDsdfme() {
        if (typeof window.DSDFME_AUTO_INIT === "function") {
            window.DSDFME_AUTO_INIT();
            return;
        }
        if (window.Plugins && window.Plugins.dsdfme_auto && typeof window.Plugins.dsdfme_auto.init === "function") {
            window.Plugins.dsdfme_auto.init();
        }
    }

    showWatermark();
    addCss("static/plugins/receiver/dsdfme_auto/dsdfme_auto.css");
    addScript("static/plugins/receiver/dsdfme_auto/dsdfme_auto.js", bootDsdfme);
    setTimeout(bootDsdfme, 0);
})();
