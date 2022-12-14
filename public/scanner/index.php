<!DOCTYPE html>
<html lang="en">

<head>
    <title>Scanner.js demo: Scan PDF to Form</title>
    <meta charset='utf-8'>
    <script src="https://cdn.asprise.com/scannerjs/scanner.js" type="text/javascript"></script>

    <script>
        //
        // Please read scanner.js developer's guide at: http://asprise.com/document-scan-upload-image-browser/ie-chrome-firefox-scanner-docs.html
        //

        /** Scan: output PDF original and JPG thumbnails */
        function scanToPdfWithThumbnails() {
            scanner.scan(displayImagesOnPage, {
                "output_settings": [{
                        "type": "return-base64",
                        "format": "pdf",
                        "pdf_text_line": "By ${USERNAME} on ${DATETIME}"
                    },
                    {
                        "type": "return-base64-thumbnail",
                        "format": "jpg",
                        "thumbnail_height": 200
                    }
                ]
            });
        }

        /** Processes the scan result */
        function displayImagesOnPage(successful, mesg, response) {
            if (!successful) { // On error
                console.error('Failed: ' + mesg);
                return;
            }

            if (successful && mesg != null && mesg.toLowerCase().indexOf('user cancel') >= 0) { // User cancelled.
                console.info('User cancelled');
                return;
            }

            var scannedImages = scanner.getScannedImages(response, true, false); // returns an array of ScannedImage
            for (var i = 0;
                (scannedImages instanceof Array) && i < scannedImages.length; i++) {
                var scannedImage = scannedImages[i];
                processOriginal(scannedImage);
            }

            var thumbnails = scanner.getScannedImages(response, false, true); // returns an array of ScannedImage
            for (var i = 0;
                (thumbnails instanceof Array) && i < thumbnails.length; i++) {
                var thumbnail = thumbnails[i];
                processThumbnail(thumbnail);
            }
        }

        /** Images scanned so far. */
        var imagesScanned = [];

        /** Processes an original */
        function processOriginal(scannedImage) {
            imagesScanned.push(scannedImage);
        }

        /** Processes a thumbnail */
        function processThumbnail(scannedImage) {
            var elementImg = scanner.createDomElementFromModel({
                'name': 'img',
                'attributes': {
                    'class': 'scanned',
                    'src': scannedImage.src
                }
            });
            document.getElementById('images').appendChild(elementImg);
        }

        /** Upload scanned images by submitting the form */
        function submitFormWithScannedImages() {
            if (scanner.submitFormWithImages('form1', imagesScanned, function(xhr) {
                    if (xhr.readyState == 4) { // 4: request finished and response is ready
                        document.getElementById('server_response').innerHTML = "<h2>Response from the server: </h2>" + xhr.responseText;
                        document.getElementById('images').innerHTML = ''; // clear images
                        imagesScanned = [];
                    }
                })) {
                document.getElementById('server_response').innerHTML = "Submitting, please stand by ...";
            } else {
                document.getElementById('server_response').innerHTML = "Form submission cancelled. Please scan first.";
            }
        }
    </script>

    <style>
        img.scanned {
            height: 200px;
            /** Sets the display size */
            margin-right: 12px;
        }

        div#images {
            margin-top: 20px;
        }
    </style>
</head>

<body>

    <h2>Scanner.js: Scan PDF to Form and then Submit</h2>

    <button type="button" onclick="scanToPdfWithThumbnails();">Scan</button>

    <div id="images"></div>

    <!-- Previous lines are same as demo-01, below is new addition to demo-02 -->

    <form id="form1" action="http://192.168.2.30/antrian/public/scanner/real.php?action=upload" method="POST" enctype="multipart/form-data" target="_blank">
        <input type="text" id="norm" name="norm" value="Test scan" placeholder="No RM" />
        <input type="button" value="Submit" onclick="submitFormWithScannedImages();">
    </form>

    <div id="server_response"></div>

    <!-- HELP_LINKS_START help links at the bottom -->
    <style>
        .asprise-footer,
        .asprise-footer a:visited {
            font-family: Arial, Helvetica, sans-serif;
            color: #999;
            font-size: 13px;
        }

        .asprise-footer a {
            text-decoration: none;
            color: #999;
        }

        .asprise-footer a:hover {
            padding-bottom: 2px;
            border-bottom: solid 1px #9cd;
            color: #06c;
        }
    </style>
    <div class="asprise-footer" style="margin-top: 48px;">
        <a href="http://asprise.com/document-scan-upload-image-browser/direct-to-server-php-asp.net-overview.html" target="_blank" title="Opens in new tab">Scanner.js Homepage</a> |
        <a href="http://asprise.com/scan/scannerjs/docs/html/scannerjs-javascript-guide.html" target="_blank" title="Opens in new tab">Developer's Guide to ScannerJs</a> |
        <a href="https://github.com/Asprise/scannerjs.javascript-scanner-access-in-browsers-chrome-ie.scanner.js" target="_blank" title="Opens in new tab">Sample code on Github</a>
    </div>
    <!-- HELP_LINKS_END -->
</body>

</html>
