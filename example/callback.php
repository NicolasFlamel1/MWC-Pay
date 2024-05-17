<?php

	# Run with: sudo -u www-data php -S localhost:9012 callback.php
	
	// Included files
	require __DIR__ . "/items.php";
	
	// Check if session or items aren't provided
	if(array_key_exists(session_name(), $_GET) === FALSE || mb_strlen($_GET[session_name()]) === 0 || array_key_exists("items", $_GET) === FALSE || preg_match('/^(?:\d+,)*\d+$/u', $_GET["items"]) !== 1) {
	
		// Return bad request response and exit
		http_response_code(400);
		exit;
	}
	
	// Set session ID to the provided session
	session_id($_GET[session_name()]);
	
	// Check if resuming session failed
	if(session_start() === FALSE) {
	
		// Return internal server error response and exit
		http_response_code(500);
		exit;
	}
	
	// Go through all item IDs
	foreach(explode(",", $_GET["items"]) as $id) {
	
		// Check if item is valid
		if(array_key_exists((int)$id, ITEMS) === TRUE) {
	
			// Check if session's purchased doesn't exist
			if(array_key_exists("purchased", $_SESSION) === FALSE) {
			
				// Create session's purchased
				$_SESSION["purchased"] = [];
			}
			
			// Append item to the session's purchased
			$_SESSION["purchased"][] = (int)$id;
		}
	}
?>
