// The encryption potion of the code was written by meixler, you can find it here https://github.com/meixler/web-browser-based-file-encryption-decryption
// All cryptography operations are implemented using using the Web Crypto API. Files are encrypted using AES-CBC 256-bit symmetric encryption. The encryption key is derived from the password and a random salt using PBKDF2 derivation with 10000 iterations of SHA256 hashing.

var mode = null;
var objFile = null;
var encryptemessagemode = false;
var originalfilename = "plaintext.txt";
var deleteondownload = false;
var objurl = null;
var plaintext = null;
var downloadedcipherbytes = null;
var tempkey = uuidv4();
var anchorkey = window.location.hash.substring(1);
var objmetadata = null;
var downloadurl = null;
var infected = false;

// Set onclick events for our page so we can lock it down using CSP.

btnDecrypt.onclick = function(){decryptfile()};
bCopyText.onclick = function(){copytextarea()};
aDecsavefile.onclick = function(){javascript:postdownloadaction()};
bDeleteFile.onclick = function(){deletefile()};
datastoreregion="us"

regions = {"au": "Australia","us" : "United States", "eu": "Europe"}
//---------------------------------------------------//
objurl = getUrlVars()["obj"]
if (objurl != undefined) {
    datastoreregion=getUrlVars()["region"]
    bFileRegion.innerText = regions[datastoreregion]
    getMetadata(objurl);
} else {
    btnDecrypt.disabled = true;
}

function uuidv4() {
    return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
        (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    );
}


function getUrlVars() {
    urlwithoutanchor=window.location.href.split("#")[0]
    var vars = {};
    var parts = urlwithoutanchor.replace(/[?&]+([^=&]+)=([^&]*)/gi, function (m, key, value) {
        vars[key] = value;
    });
    return vars;
}

async function getMetadata(objurl) {
    var body = document.body;
    body.classList.add("loading");
    let url = lambdaurl + objurl + "?region=" + datastoreregion;
    console.log(url)
    response = await fetch(url)
    if (response.status == 404) {
        bFilename.innerText = "Failed to fetch metadata - File may no longer exist.";
        btnDecrypt.disabled = true;
        body.classList.remove("loading");
        return
    }
    data = await response.json()
    objmetadata = data;
    ss = String(objmetadata.objsize) + " Bytes"
    if ((objmetadata.objsize / 1048576) > 1) {
        ss = String((objmetadata.objsize / 1048576).toFixed(0)) + " Mb";
    } else if ((objmetadata.objsize / 1024) > 1) {
        ss = String((objmetadata.objsize / 1024).toFixed(0)) + " Kb"
    }
    originalfilename = data.objname.replace(/[^A-Za-z0-9\-\_\.]/g, '');
    bFilename.innerText = originalfilename;
    bFilesize.innerText = ss;
    await decryptfile(decryptonvisit=true);
    body.classList.remove("loading");
}

// Check for virus is best effort because the site is not open to public which greatly reduce chances of being abused
async function checkforvirus(filehash) {
    let url = lambdaurl + "/sha1/"+filehash + "?region=" + datastoreregion;
    response = await fetch(url);
    data = await response.json()

    vtlink = data.vtlink
    if (response.status != 200){
        // IF response is not 200, return immediately
        return
    }
    if (data.detect){
        console.log("Virus total detected!");
        spnDecstatus.classList.remove("greenspan");
        spnDecstatus.classList.add("redspan");
        spnDecstatus.innerHTML = "<h3 style='color:red'>VIRUS DETECTED</h3> <a target='_blank' href='"+vtlink+"'>Visit virustotal result("+data.positives+"/"+data.total+" detected)</a>"
        document.body.style.background="#ff9966";
        bDownloadDecFile.innerText = "Ignore & Download anyway"
        infected = true;
    } else {
        spnDecstatus.classList.remove("redspan");
        spnDecstatus.classList.add("greenspan");
        spnDecstatus.innerText = "No known threat found!"
        console.log("No known threat is found!");
    }
    
}

async function downloadFromS3() {
    var url = objmetadata.signedurl
    const response = await fetch(url)
    
    if (response.status != 200) {
        spnDecstatus.innerText = "FAILED to download"
        return
    }
    console.log(response.headers.get("x-amz-meta-tag"))
    try {
        filemetadata = JSON.parse(response.headers.get("x-amz-meta-tag"));
    } catch {
        filemetadata = {name:"plain.dec",deleteondownload:false};
    }
    if (filemetadata.name != "") {
        originalfilename = filemetadata.name.replace(/[^A-Za-z0-9\-\_\.]/g, '');;
    }
    if (originalfilename == "messageinbrowser.txt") {
        encryptemessagemode = true;
    }
    deleteondownload = filemetadata.deleteondownload;

    buff = await response.arrayBuffer();
    downloadedcipherbytes = new Uint8Array(buff)
    modalstatus.innerText="Decrypting binary blob";
    return downloadedcipherbytes
}

async function deletefile() {
    var deleteurl = lambdaurl + "delete/" + objurl + "?region=" + datastoreregion
    const response = await fetch(deleteurl)
    bDownloadDecFile.innerText = "Save File or Lose it"
    if (response.status != 200) {
        spnDecstatus.classList.remove("greenspan");
        spnDecstatus.classList.add("redspan");
        spnDecstatus.innerHTML += "Failed to delete object"
        return
    } else {
        spnDecstatus.innerHTML = "File is deleted from the server."
    }
}


function copytextarea() {
    let textarea = document.getElementById("textareaDecryptmessage");
    textarea.select();
    document.execCommand("copy");
  }


async function decryptfile(decryptonvisit=false) {
    var body = document.body;
    body.classList.add("loading");
    var cipherbytes = downloadedcipherbytes;
    if (downloadedcipherbytes == null){
        modalstatus.innerText="Downloading from S3";
        var cipherbytes = await downloadFromS3();
    }
    modalstatus.innerText="Decrypting file using anchor key and user provided key";
    var pbkdf2iterations = 10000;
    var passphrasebytes = new TextEncoder("utf-8").encode(txtDecpassphrase.value + anchorkey);
    var pbkdf2salt = cipherbytes.slice(8, 16);


    var passphrasekey = await window.crypto.subtle.importKey('raw', passphrasebytes, { name: 'PBKDF2' }, false, ['deriveBits'])
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");

        });
    console.log('passphrasekey imported');

    var pbkdf2bytes = await window.crypto.subtle.deriveBits({ "name": 'PBKDF2', "salt": pbkdf2salt, "iterations": pbkdf2iterations, "hash": 'SHA-256' }, passphrasekey, 384)
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });
    console.log('pbkdf2bytes derived');
    pbkdf2bytes = new Uint8Array(pbkdf2bytes);

    keybytes = pbkdf2bytes.slice(0, 32);
    ivbytes = pbkdf2bytes.slice(32);
    cipherbytes = cipherbytes.slice(16);

    var key = await window.crypto.subtle.importKey('raw', keybytes, { name: 'AES-CBC', length: 256 }, false, ['decrypt'])
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });
    console.log('key imported');

    var plaintextbytes = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv: ivbytes }, key, cipherbytes)
        .catch(function (err) {
            console.error(err);
            body.classList.remove("loading");
        });
    if (decryptonvisit  && !plaintextbytes ){
        console.log("Could not decrypt the file without user key")
        body.classList.remove("loading");
        return
    }
    if (!plaintextbytes) {
        spnDecstatus.classList.remove("greenspan");
        spnDecstatus.classList.add("redspan");
        spnDecstatus.innerHTML = '<p>Error decrypting file.  Password may be incorrect.</p>';
        body.classList.remove("loading");
        return;
    }

    console.log('ciphertext decrypted');
    plaintextbytes = new Uint8Array(plaintextbytes);

    var blob = new Blob([plaintextbytes], { type: 'application/download' });
    var blobUrl = URL.createObjectURL(blob);
    aDecsavefile.href = blobUrl;
    aDecsavefile.download = originalfilename;
    spnDecstatus.classList.remove("redspan");
    spnDecstatus.classList.add("greenspan");
    spnDecstatus.innerHTML = '<p>File decrypted.</p>';
    divDecsavefile.hidden = false;
    aDeleteFile.hidden = false;
    modalstatus.innerText="Checking file hash of the file with Virustotal";
    filehash= await sha1(plaintextbytes);
    await checkforvirus(filehash);
    // If this is a message send in browser, show it.
    body.classList.remove("loading");
    divDecryptInfo.style.display = "none";
    divDecryptResult.style.display = ""
    if (encryptemessagemode)
    {
        textareaDecryptmessage.value =  new TextDecoder("utf-8").decode(plaintextbytes);
        bCopyText.hidden = false;
        divDecryptmessage.style.display = "";
    }
    fileextension = originalfilename.substr(-4)
    
    switch (fileextension) {
        case ".png":
            updateimgtag("png",plaintextbytes);
            break;
        case ".jpg":
            updateimgtag("jpg",plaintextbytes);
            break;
        case "jpeg":
            updateimgtag("jpeg",plaintextbytes);
            break;
        case ".gif":
            updateimgtag("gif",plaintextbytes);
            break;
        
    }
    if (deleteondownload) {
        deletefile();
    } else {
        aDeleteFile.hidden = false;
    }
}

function Uint8ToString(u8a){
    var CHUNK_SZ = 0x8000;
    var c = [];
    for (var i=0; i < u8a.length; i+=CHUNK_SZ) {
      c.push(String.fromCharCode.apply(null, u8a.subarray(i, i+CHUNK_SZ)));
    }
    return c.join("");
  }

function updateimgtag(extension,plaintextbytes){
    var b64encoded = btoa(Uint8ToString(plaintextbytes));
    divDecryptImage.style.display = "block"
    imgDecryptImage.src = "data:image/"+extension+";base64,"+b64encoded;
}

function postdownloadaction(){
    if (deleteondownload) {
        // deletefile();
        return
    }
}
function buf2hex(buffer) { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

async function sha1(data) {
    hash = await crypto.subtle.digest('SHA-1', data);
    return buf2hex(hash);
  }

function showmoredecryptioninfo(){
    divExtraDecResult.style.display="block";
    bShowExtraInfo.style.display="none";
}