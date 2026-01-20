# CTF League - porygons and polyglots

## Polyglots

A Polyglot is a method of creating single files that are valid in multiple file formats, or that contain hidden files within, and are common tool used to disguise malware. The simplest method of doing this is by appending the bytes of one file to another. Many tools such as exiftool may find the files as malformed, for example it flagged the png files for having excess data after the IEND bytes, but it is still properly interpreted as a png by most all applications, while containg arbitrary and potentially malicious data within.

## Challenge
For this challenge, we were provided with an file download, that appeared as an wav file, that we were eventually able to discover was also a zip archive that could be unzipped for further files which contained fragments of the flag. 

### Flag Fragment 1
Among the unzipped files was a png file `porygon`. The PNG file type a consistent ending byte sequence known as the IEND bytes, made up of 4 bytes of zeros, the string IEND and a cyclic redundancy check. Finding this sequence in a hex editor, there was considerable amount of data following it. This data when copied to its own file made up an mp3 file, which played a brief morse code message. We were eventually able to transcribe the morse code as ". ...- ---" or "Evo" which was the first fragment of the flag.

### Flag Fragment 2
We were able to determine the filetype of porygon to be a png by looking at the metadata using a command line utility `exiftool`. Among the metadata it found was a comment field which contained the data "Flag Frac 2: lvi"

### Flag Fragment 3
Examining the raw bytes of the pdf file produced from unzipping the original file in a hex editor we found some unusual human readable text:
```js
atob("ZmxhZyBmcmFjdGlvbiAzOiBuZ18=")
```
Recognizing this as the javascript for decoding a base64-encoded string, we decoded the data to find the third flag fragment "flag fraction 3: ng_"

### Flag Fragment 4
The raw bytes of that pdf also contained the following html paragraph element.
```html
<p>My favorite pokemon are weepingbell, marowak, lickitung in that exact order for definitely no reason</p>
```
Looking at the actual pdf contents in a browser, the document is a table of pokemon indexed by ids, and the three pokemon mentioned in the text corresponded to the indices 70 105 and 108 respectively, and subsequently the ascii string "Fil". 

### Flag Fragment 5
The unzipped file `porygon-z` was much larger (200Kb) that an image of its logically should be which gave us the impression there might be another layer of file hidden within it. Using the same IEND method as fragment 1, we extracted the extra data into another file which formed a valid pdf file. Opening the pdf, there was a string of invisible text that we copied out of the document that made up the 5th flag fragment "Flag Fraction 5: ety"

### Flag Fragment 6
The unzipped `porygon-z` file metadata, which we able to inspect with exiftool similar to fragment 2 contained another custom field with the data "Synt Senpgvba 6: crf". This cipher maintained structure and numeric/special characters of the original plaintext which is a telltale sign of a ceaser cipher, specifically rot13 cipher, which decoded gave the final fragment "Flag Fraction 6: pes"

