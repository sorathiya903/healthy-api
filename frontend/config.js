const API_BASE_URL="https://healthy-api-z0mi.onrender.com"
// 1. Define your debug condition (can be a boolean variable, URL parameter, or localStorage flag)
const isDebug = true; 

if (isDebug) {
    // 2. Create the script element
    const script = document.createElement('script');
    script.src = "https://cdn.jsdelivr.net/npm/eruda"
    script.async = true;

    // 3. Initialize Eruda once the script has successfully finished loading
    script.onload = function () {
        eruda.init();
        console.log("Eruda developer tools initialized.");
    };

    // 4. Inject the script into the document head or body
    document.head.appendChild(script);
}
// 1. Create a new link element
const link = document.createElement('link');

// 2. Set the required attributes
link.rel = 'icon';
link.type = 'image/png';
link.href = 'favicon.png';

// 3. Append it to the head section
document.head.appendChild(link);
