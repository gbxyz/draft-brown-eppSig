<?php

/* load libs ******************************************************************/
require('cnic/epp/lib/EPP/FrameValidator.php');

require('xmlseclibs/xmlseclibs.php');

/* build XML ******************************************************************/

$xml = '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <command>
    <create>
      <domain:create xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>example.com</domain:name>
        <domain:period unit="y">2</domain:period>
        <domain:ns>
          <domain:hostObj>ns1.example.com</domain:hostObj>
          <domain:hostObj>ns2.example.com</domain:hostObj>
        </domain:ns>
        <domain:registrant>jd1234</domain:registrant>
        <domain:contact type="admin">sh8013</domain:contact>
        <domain:contact type="tech">sh8013</domain:contact>
        <domain:authInfo>
          <domain:pw>2fooBAR</domain:pw>
        </domain:authInfo>
      </domain:create>
    </create>
    <extension>
      <secDNS:create xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
        <secDNS:maxSigLife>604800</secDNS:maxSigLife>
        <secDNS:dsData>
          <secDNS:keyTag>12345</secDNS:keyTag>
          <secDNS:alg>3</secDNS:alg>
          <secDNS:digestType>1</secDNS:digestType>
          <secDNS:digest>49FD46E6C4B45C55D4AC</secDNS:digest>
        </secDNS:dsData>
      </secDNS:create>
      <eppSig:signature xmlns:eppSig="urn:centralnic:params:xml:ns:eppSig-1.0" />
    </extension>
    <clTRID>ABC-12345</clTRID>
  </command>
</epp>';

$doc = new DOMDocument;

$doc->loadXML($xml);

$extn = $doc->getElementsByTagNameNS('urn:centralnic:params:xml:ns:eppSig-1.0', 'signature')->item(0);

if (!$extn) die("Can't find element");

/* build sig ******************************************************************/

$objDSig = new XMLSecurityDSig();

$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

$objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));

$objKey->loadKey('xmlseclibs/tests/privkey.pem', TRUE);

$objDSig->sign($objKey);

$objDSig->appendSignature($extn);

/* validate doc ***************************************************************/

$validator = new EPP_FrameValidator;

$xml = $doc->saveXML();

$lines = explode("\n", $xml);
$fmt = sprintf("%%0%dd: %%s\n", strlen(count($lines)));
for ($i = 0 ; $i < count($lines) ; $i++) printf($fmt, $i+1, $lines[$i]);

if (!$validator->validate($xml)) {
	foreach ($validator->errors as $error) printf("Line %d: %s\n", $error->line, $error->message);

} else {
	print "Document is valid\n";

}

/* verify sig *****************************************************************/

$objXMLSecDSig = new XMLSecurityDSig();

$objDSig = $objXMLSecDSig->locateSignature($doc);
$objXMLSecDSig->canonicalizeSignedInfo();

$objKey = $objXMLSecDSig->locateKey();
$objKey->loadKey('xmlseclibs/tests/mycert.pem', TRUE);

if ($objXMLSecDSig->verify($objKey)) {
	print "Signature validates\n";

} else {
	print "Signature is not valid\n";
}

