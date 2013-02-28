/* -------------------------------------------------------------------------- *
 * file:         webcert.js                                                   *
 * purpose:      provide javascript functions to WebCert's HTML forms         *
 * ---------------------------------------------------------------------------*/

function elementHideShow(element) {
  var el = document.getElementById(element);
  if (el.style.display == "block") { el.style.display = "none"; }
  else { el.style.display = "block"; }
}

function switchGrey(src, dst1, dst2) {
  var s = document.getElementById(src);
  var d1 = document.getElementById(dst1);
  var d2 = document.getElementById(dst2);
  if (s.checked == true) { d1.style.backgroundColor = "#FFFFFF"; d2.style.backgroundColor = "#CFCFCF"; }
  else {  d1.style.backgroundColor = "#CFCFCF"; }
}
