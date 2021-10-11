<?php

include "VanguardClient.php";

$record = array(
    'OrgCode' => 'VA1803',
    'USI'     => 'GSR3R49PPX',
    'FirstName' => 'margaret',
    'FamilyName' => 'Michael',
    'DateOfBirth' => '1990-05-31'
);

try {
    $usi = new VanguardClient('TEST', 'keystore-test.xml', 'Password1!', 'ABRD:27809366375_USIMachine');
    $response = $usi->verifyUSI(
        $record['OrgCode'], 
        $record['USI'], 
        $record['FirstName'], 
        $record['FamilyName'], 
        $record['DateOfBirth']
    /* './' optional path to dump requests and responses */);
    print_r($response);
    
} catch (Exception $e) {
    echo $e->getMessage();
}
