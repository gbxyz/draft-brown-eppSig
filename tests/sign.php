<?php

// sign an EPP frame

require('xmlseclibs.php');

$doc = DOMDocument::load('unsigned.xml');
if (!$doc) die("Error: couldn't load unsigned.xml!");

$extn = $doc->getElementsByTagNameNS('urn:centralnic:params:xml:ns:eppSig-1.0', 'signature')->item(0);

if (!$extn) die("Error: Can't find eppSig element in unsigned.xml!");

$objDSig = new XMLSecurityDSig();

$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

$objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));

$objKey->loadKey('private.key', true);

$objDSig->sign($objKey);

$objDSig->appendSignature($extn);

$doc->save('signed.xml');

print "Signed frame saved to signed.xml\n";
