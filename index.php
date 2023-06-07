<?php

include "VanguardClient.php";

$record = array(
    'OrgCode' => 'VA1803', // VA1803
    'USI'     => 'BNGH7C75FN',
    'FirstName' => 'Maryam',
    'FamilyName' => 'Fredrick',
    'DateOfBirth' => '1983-06-13'
);


try {
    $usi = new VanguardClient('TEST', 'keystore-test.xml', 'Password1!', 'ABRD:27809366375_USIMachine', '/home/www/m2m-php/trace');

    $expired = $usi->hasExpired();
    $r =(object) array('Expired' => $expired);
    //echo json_encode($r) . "\n";
    if ($expired) {
       echo "Key store has expired quitting\n";
       exit;
    }

    $response = $usi->verifyUSI(
        $record['OrgCode'], 
        $record['USI'], 
        $record['FirstName'], 
        $record['FamilyName'], 
        $record['DateOfBirth']
    /* './' optional path to dump requests and responses */);
    echo json_encode($response) . "\n";
    
} catch (Exception $e) {
    echo $e->getMessage();
}
