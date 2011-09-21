<?php

// verify a signed EPP frame

require('xmlseclibs.php');

$doc = DOMDocument::load('signed.xml');
if (!$doc) die("Error: couldn't load signed.xml!");

$objXMLSecDSig = new XMLSecurityDSig();

$objDSig = $objXMLSecDSig->locateSignature($doc);
$objXMLSecDSig->canonicalizeSignedInfo();

$objKey = $objXMLSecDSig->locateKey();
$objKey->loadKey('public.key', TRUE);

if ($objXMLSecDSig->verify($objKey)) {
	print "Signature validates\n";

} else {
	die("Error: signature isn't valid!");

}

