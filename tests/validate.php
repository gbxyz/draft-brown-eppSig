<?php

// validate a signed EPP frame

$doc = DOMDocument::load('signed.xml');
if (!$doc) die("Error: couldn't load signed.xml!");

libxml_use_internal_errors(true);

if (!$doc->schemaValidate('xsd/epp.xsd')) {
	foreach (libxml_get_errors() as $error) die(sprintf("Error (line %d, column %d): %s", $error->line, $error->column, $error->message));

} else {
	print "Signed frame passed schema validation\n";

}
