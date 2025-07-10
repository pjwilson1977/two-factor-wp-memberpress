<?php
/**
 * Template functions for Two-Factor Authentication Setup
 */

/**
 * Render setup step
 */
function render_setup_step( $user ) {
	// Validate user object
	if ( ! $user || ! $user->ID ) {
		error_log( 'ERROR: Invalid user object passed to render_setup_step' );
		echo '<div class="error-message">Session expired. Please try logging in again.</div>';
		return;
	}
	
	error_log( 'render_setup_step called with valid user: ' . $user->user_login . ' (ID: ' . $user->ID . ')' );
	
	$providers = Two_Factor_Core::get_providers();
	if ( ! isset( $providers['Two_Factor_Totp'] ) ) {
		error_log( 'ERROR: TOTP provider not available in render_setup_step' );
		return;
	}
	
	$totp_provider = $providers['Two_Factor_Totp'];
	$secret = get_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, true );
	
	if ( ! $secret ) {
		error_log( 'No secret found in render_setup_step, generating new one for user ' . $user->ID );
		// Generate new secret if none exists
		$secret = $totp_provider->generate_key();
		update_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, $secret );
		error_log( 'Generated new secret for user ' . $user->ID . ': ' . substr( $secret, 0, 10 ) . '...' );
	} else {
		error_log( 'Found existing secret for user ' . $user->ID . ': ' . substr( $secret, 0, 10 ) . '...' );
	}
	
	$qr_url = $totp_provider->generate_qr_code_url( $user, $secret );
	error_log( 'Generated QR URL: ' . $qr_url );
	$qr_svg_url = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode( $qr_url );
	error_log( 'QR SVG URL: ' . $qr_svg_url );
	?>
	<div class="setup-step">
		<div class="setup-header">
			<h2><?php _e( 'Step 1: Install Authenticator App', 'two-factor' ); ?></h2>
			<div class="setup-instructions">
				<p><?php _e( 'Install an authenticator app on your phone:', 'two-factor' ); ?></p>
				<ul>
					<li><?php _e( 'Google Authenticator (iOS/Android)', 'two-factor' ); ?></li>
					<li><?php _e( 'Microsoft Authenticator (iOS/Android)', 'two-factor' ); ?></li>
					<li><?php _e( 'Authy (iOS/Android/Desktop)', 'two-factor' ); ?></li>
				</ul>
			</div>

			<h2><?php _e( 'Step 2: Scan QR Code', 'two-factor' ); ?></h2>
			<div class="qr-code">
				<img src="<?php echo esc_url( $qr_svg_url ); ?>" alt="<?php _e( 'QR Code for Two-Factor Authentication', 'two-factor' ); ?>" />
			</div>
			
			<div class="setup-instructions">
				<p><?php _e( 'Open your authenticator app and scan the QR code above, or manually enter this secret key:', 'two-factor' ); ?></p>
				<p><strong><?php echo esc_html( $secret ); ?></strong></p>
				
				<?php
				// Show user what to expect in their authenticator app
				$site_name = get_bloginfo( 'name', 'display' );
				$user_identifier = ! empty( $user->user_email ) ? $user->user_email : ( ! empty( $user->display_name ) ? $user->display_name : $user->user_login );
				?>
				<p><strong><?php _e( 'Expected account name in your app:', 'two-factor' ); ?></strong><br>
				<?php echo esc_html( $site_name . ':' . $user_identifier ); ?></p>
			</div>

			<form method="get" action="" class="two-factor-form">
				<input type="hidden" name="two_factor_setup" value="1" />
				<input type="hidden" name="step" value="verify" />
				<input type="hidden" name="setup_confirmed" value="1" />
				<p>
					<input type="submit" 
						   class="btn btn-primary btn-full-width" 
						   value="<?php esc_attr_e( 'I\'ve Added the Account to My App', 'two-factor' ); ?>" />
				</p>
			</form>
		</div>
	</div>
	<?php
}

/**
 * Render verify step
 */
function render_verify_step( $user ) {
	$error = isset( $_GET['error'] ) ? sanitize_text_field( $_GET['error'] ) : '';
	?>
	<div class="setup-step">
		<div class="setup-header">
			<h2><?php _e( 'Step 3: Verify Setup', 'two-factor' ); ?></h2>
			<p><?php _e( 'Enter the 6-digit code from your authenticator app to verify the setup:', 'two-factor' ); ?></p>
		</div>

		<?php if ( $error === 'invalid_code' ): ?>
			<div class="two-factor-message error">
				<p><?php _e( 'Invalid verification code. Please try again.', 'two-factor' ); ?></p>
			</div>
		<?php elseif ( $error === 'no_secret' ): ?>
			<div class="two-factor-message error">
				<p><?php _e( 'Setup not found. Please start over.', 'two-factor' ); ?></p>
			</div>
		<?php endif; ?>

		<form method="post" action="" class="two-factor-form">
			<?php wp_nonce_field( 'two_factor_setup_verify', '_wpnonce' ); ?>
			<input type="hidden" name="two_factor_setup_action" value="verify_totp" />
			
			<div class="form-field">
				<label for="totp_code">
					<?php _e( 'Authentication Code', 'two-factor' ); ?>
				</label>
				<input type="text" 
					   id="totp_code" 
					   name="totp_code" 
					   maxlength="6" 
					   pattern="[0-9]{6}" 
					   autocomplete="one-time-code" 
					   required 
					   placeholder="000000" />
			</div>
			
			<p>
				<input type="submit" 
					   class="btn btn-primary btn-full-width" 
					   value="<?php esc_attr_e( 'Verify Code', 'two-factor' ); ?>" />
			</p>
		</form>

		<p>
			<a href="<?php echo esc_url( add_query_arg( array( 'two_factor_setup' => '1', 'step' => 'setup' ), home_url() ) ); ?>" class="btn btn-secondary">
				<?php _e( 'Back to Setup', 'two-factor' ); ?>
			</a>
		</p>
	</div>
	<?php
}

/**
 * Render backup codes step
 */
function render_backup_codes_step( $user ) {
	// Get backup codes for the user
	$providers = Two_Factor_Core::get_providers();
	$backup_codes = array();
	
	if ( isset( $providers['Two_Factor_Backup_Codes'] ) ) {
		$backup_provider = $providers['Two_Factor_Backup_Codes'];
		$backup_codes = $backup_provider->get_codes( $user );
		
		if ( empty( $backup_codes ) ) {
			$backup_codes = $backup_provider->generate_codes( $user );
		}
	}
	?>
	<div class="setup-step">
		<div class="setup-header">
			<h2><?php _e( 'Step 4: Save Your Backup Codes', 'two-factor' ); ?></h2>
			<p><?php _e( 'These backup codes can be used to access your account if you lose access to your authenticator app. Save them in a secure location.', 'two-factor' ); ?></p>
		</div>

		<?php if ( ! empty( $backup_codes ) ): ?>
			<div class="two-factor-backup-codes">
				<h3><?php _e( 'Your Backup Codes', 'two-factor' ); ?></h3>
				<p><?php _e( 'Each code can only be used once. Store these codes safely.', 'two-factor' ); ?></p>
				
				<ul class="two-factor-backup-codes-list">
					<?php foreach ( $backup_codes as $code ): ?>
						<li><?php echo esc_html( $code ); ?></li>
					<?php endforeach; ?>
				</ul>
				
				<button type="button" onclick="copyBackupCodes()" class="btn btn-secondary">
					<?php _e( 'Copy Codes', 'two-factor' ); ?>
				</button>
				
				<button type="button" onclick="downloadBackupCodes()" class="btn btn-secondary">
					<?php _e( 'Download Codes', 'two-factor' ); ?>
				</button>
			</div>
		<?php else: ?>
			<div class="two-factor-message error">
				<p><?php _e( 'Unable to generate backup codes. You can generate them later from your profile.', 'two-factor' ); ?></p>
			</div>
		<?php endif; ?>

		<form method="post" action="" class="two-factor-form">
			<?php wp_nonce_field( 'two_factor_setup_backup', '_wpnonce' ); ?>
			<input type="hidden" name="backup_codes_acknowledged" value="1" />
			
			<div class="form-field">
				<label>
					<input type="checkbox" name="codes_saved" required />
					<?php _e( 'I have saved these backup codes in a secure location', 'two-factor' ); ?>
				</label>
			</div>
			
			<p>
				<input type="submit" 
					   class="btn btn-primary btn-full-width" 
					   value="<?php esc_attr_e( 'Complete Setup', 'two-factor' ); ?>" />
			</p>
		</form>
	</div>

	<script>
	function copyBackupCodes() {
		const codes = <?php echo json_encode( $backup_codes ); ?>;
		const codesText = codes.join('\n');
		
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(codesText).then(() => {
				alert('<?php _e( 'Backup codes copied to clipboard!', 'two-factor' ); ?>');
			});
		} else {
			// Fallback for older browsers
			const textArea = document.createElement('textarea');
			textArea.value = codesText;
			document.body.appendChild(textArea);
			textArea.select();
			document.execCommand('copy');
			document.body.removeChild(textArea);
			alert('<?php _e( 'Backup codes copied to clipboard!', 'two-factor' ); ?>');
		}
	}
	
	function downloadBackupCodes() {
		const codes = <?php echo json_encode( $backup_codes ); ?>;
		const codesText = codes.join('\n');
		const blob = new Blob([codesText], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'two-factor-backup-codes.txt';
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}
	</script>
	<?php
}

/**
 * Render complete step
 */
function render_complete_step( $user ) {
	?>
	<div class="setup-step">
		<div class="success-message">
			<h2><?php _e( 'Setup Complete!', 'two-factor' ); ?></h2>
			<p><?php _e( 'Two-factor authentication has been successfully enabled for your account.', 'two-factor' ); ?></p>
		</div>
		
		<div class="setup-instructions">
			<p><?php _e( 'You can now log in to your account using your username, password, and authentication code from your app.', 'two-factor' ); ?></p>
		</div>

		<form method="post" action="">
			<p>
				<a href="<?php echo esc_url( home_url() ); ?>" class="btn btn-primary btn-full-width">
					<?php _e( 'Continue to Site', 'two-factor' ); ?>
				</a>
			</p>
		</form>
	</div>
	<?php
}

// Get user from session storage (like the main plugin does)
if ( ! session_id() ) {
	session_start();
}

$user = null;
if ( isset( $_SESSION['two_factor_setup_user_id'] ) && isset( $_SESSION['two_factor_setup_timestamp'] ) ) {
	// Check if session is still valid (30 minutes)
	if ( time() - $_SESSION['two_factor_setup_timestamp'] <= 1800 ) {
		$user = get_user_by( 'id', $_SESSION['two_factor_setup_user_id'] );
	}
}

// Fallback to wp_get_current_user if no session user found
if ( ! $user || ! $user->ID ) {
	$user = wp_get_current_user();
}

$step = isset( $_GET['step'] ) ? sanitize_text_field( $_GET['step'] ) : 'setup';

// Debug user information
error_log( 'Template - User ID: ' . $user->ID . ', Login: ' . $user->user_login . ', Email: ' . $user->user_email );
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?php _e( 'Two-Factor Authentication Setup', 'two-factor' ); ?> | <?php bloginfo( 'name' ); ?></title>
	<?php wp_head(); ?>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			background: #f1f1f1;
			margin: 0;
			padding: 20px;
		}
		.two-factor-setup-container {
			max-width: 500px;
			margin: 0 auto;
			background: white;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 2px 10px rgba(0,0,0,0.1);
		}
		.setup-header {
			text-align: center;
			margin-bottom: 30px;
		}
		.setup-header h1 {
			color: #333;
			margin-bottom: 10px;
		}
		.setup-step {
			margin-bottom: 20px;
		}
		.setup-step h2 {
			color: #555;
			border-bottom: 2px solid #0073aa;
			padding-bottom: 10px;
		}
		.qr-code {
			text-align: center;
			margin: 20px 0;
		}
		.qr-code img {
			border: 1px solid #ddd;
			padding: 10px;
		}
		.setup-instructions {
			background: #f9f9f9;
			padding: 15px;
			border-left: 4px solid #0073aa;
			margin: 20px 0;
		}
		.form-field {
			margin-bottom: 15px;
		}
		.form-field label {
			display: block;
			margin-bottom: 5px;
			font-weight: 600;
		}
		.form-field input[type="text"] {
			width: 100%;
			padding: 10px;
			border: 1px solid #ddd;
			border-radius: 4px;
			font-size: 16px;
			box-sizing: border-box;
		}
		.btn {
			background: #0073aa;
			color: white;
			padding: 12px 24px;
			border: none;
			border-radius: 4px;
			cursor: pointer;
			font-size: 16px;
			text-decoration: none;
			display: inline-block;
		}
		.btn:hover {
			background: #005a87;
		}
		.btn-primary {
			background: #0073aa;
		}
		.btn-full-width {
			width: 100%;
			box-sizing: border-box;
			text-align: center;
		}
		.btn-secondary {
			background: #666;
			margin-left: 10px;
		}
		.btn-secondary:hover {
			background: #555;
		}
		.two-factor-message.error {
			background: #f8d7da;
			color: #721c24;
			padding: 10px;
			border: 1px solid #f5c6cb;
			border-radius: 4px;
			margin-bottom: 20px;
		}
		.success-message {
			background: #d4edda;
			color: #155724;
			padding: 15px;
			border: 1px solid #c3e6cb;
			border-radius: 4px;
			margin-bottom: 20px;
			text-align: center;
		}
		.two-factor-backup-codes {
			background: #fff3cd;
			border: 1px solid #ffeaa7;
			padding: 15px;
			border-radius: 4px;
			margin: 20px 0;
		}
		.two-factor-backup-codes-list {
			font-family: monospace;
			font-size: 14px;
			list-style: none;
			padding: 0;
			columns: 2;
			margin: 15px 0;
		}
		.two-factor-backup-codes-list li {
			margin-bottom: 5px;
			padding: 5px;
			background: white;
			border-radius: 3px;
		}
		.progress-bar {
			background: #f1f1f1;
			border-radius: 10px;
			padding: 3px;
			margin-bottom: 20px;
		}
		.progress-fill {
			background: #0073aa;
			height: 10px;
			border-radius: 8px;
			transition: width 0.3s ease;
		}
		.two-factor-form {
			margin-top: 20px;
		}
	</style>
</head>
<body>
	<div class="two-factor-setup-container">
		<div class="setup-header">
			<h1><?php _e( 'Secure Your Account', 'two-factor' ); ?></h1>
			<p><?php _e( 'Set up two-factor authentication to protect your account', 'two-factor' ); ?></p>
		</div>

		<?php
		// Progress bar
		$progress = 0;
		switch ( $step ) {
			case 'setup': $progress = 25; break;
			case 'verify': $progress = 50; break;
			case 'backup':
			case 'backup_codes': $progress = 75; break;
			case 'complete': $progress = 100; break;
		}
		?>
		<div class="progress-bar">
			<div class="progress-fill" style="width: <?php echo $progress; ?>%"></div>
		</div>

		<?php
		switch ( $step ) {
			case 'setup':
			default:
				render_setup_step( $user );
				break;
			case 'verify':
				render_verify_step( $user );
				break;
			case 'backup':
			case 'backup_codes':
				render_backup_codes_step( $user );
				break;
			case 'complete':
				render_complete_step( $user );
				break;
		}
		?>
	</div>

	<?php wp_footer(); ?>
</body>
</html>
