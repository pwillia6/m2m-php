<?php

include "vendor/autoload.php";

include "Vanguard.php";


// MAS-ST service URLs (Production Environment)
//
//https://softwareauthorisations.ato.gov.au/R3.0/S007v1.2/service.svc (SHA1)
//https://softwareauthorisations.ato.gov.au/R3.0/S007v1.3/service.svc (SHA2)
//
// MAS-ST service URLs (Test Environment)
//
//https://softwareauthorisations.acc.ato.gov.au/R3.0/S007v1.2/service.svc (SHA1)
//https://softwareauthorisations.acc.ato.gov.au/R3.0/S007v1.3/service.svc (SHA2)




// Test environment - M2M working but NOT USI >>
//const ORGCODE = 'VA1803';
//const USIRUL = 'https://3pt.portal.usi.gov.au/service/usiservice.svc';
//const VANURL = 'https://softwareauthorisations.acc.ato.gov.au/R3.0/S007v1.3/service.svc';
// <<

const ORGCODE = 'VA0094';
const USIRUL = 'https://portal.usi.gov.au/Service/UsiService.svc';
const VANURL = 'https://softwareauthorisations.ato.gov.au/R3.0/S007v1.3/service.svc';


const USI = 'GSR3R49PPX';
const FIRST = 'margaret';
const FAMILY = 'Michael';
const DOB = '1990-05-31';


$api = new VanguardClient(VANURL, USIRUL, ORGCODE, USI, FIRST, FAMILY, DOB);

// FOR TEST >>
//$api->loadAuskey('keystore-usi.xml', 'Password1!');
// <<

// MUST UPDATE KEYSTORE and PASSWORD
$api->loadAuskey('<KEYSTORE>.xml', '<PASSWORD>');

try {
    $token = $api->requestToken();
    echo "Response from ATO: <br>" . $token;
    echo "<br><br>";
    echo "Response from USI: <br>" . $api->verifyUSI($token);
} catch (Exception $e) {
    echo $e->getMessage();
}
