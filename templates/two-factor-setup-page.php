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
		echo '<div class="error-message">Session expired. Please try logging in again.</div>';
		return;
	}
	
	$providers = Two_Factor_Core::get_providers();
	if ( ! isset( $providers['Two_Factor_Totp'] ) ) {	
		return;
	}
	
	$totp_provider = $providers['Two_Factor_Totp'];
	$secret = get_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, true );
	
	if ( ! $secret ) {		
		// Generate new secret if none exists
		$secret = $totp_provider->generate_key();
		update_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, $secret );		
	} else {
		error_log( 'Found existing secret for user ' . $user->ID . ': ' . substr( $secret, 0, 10 ) . '...' );
	}
	
	$qr_url = $totp_provider->generate_qr_code_url( $user, $secret );	
	$qr_svg_url = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode( $qr_url );	
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
				<!--
				<p><strong><?php _e( 'Expected account name in your app:', 'two-factor' ); ?></strong><br>
				<?php echo esc_html( $site_name . ':' . $user_identifier ); ?></p>
				-->
			</div>

			<form method="get" action="" class="two-factor-form">
				<input type="hidden" name="two_factor_setup" value="1" />
				<input type="hidden" name="step" value="verify" />
				<input type="hidden" name="setup_confirmed" value="1" />
				<p>
					<input type="submit" 
						   class="btn btn-primary btn-full-width" 
						   value="<?php esc_attr_e( 'I\'ve Added the Account to my Authenticator App', 'two-factor' ); ?>" />
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
	// Get backup codes for the user from session (they were generated in previous step)
	if ( ! session_id() ) {
		session_start();
	}
	
	$backup_codes = array();
	if ( isset( $_SESSION['two_factor_backup_codes'] ) ) {
		$backup_codes = $_SESSION['two_factor_backup_codes'];
		// Clear them from session after displaying
		unset( $_SESSION['two_factor_backup_codes'] );
	}
	
	// If no codes in session, they may have been generated already
	if ( empty( $backup_codes ) ) {
		$providers = Two_Factor_Core::get_providers();
		if ( isset( $providers['Two_Factor_Backup_Codes'] ) ) {
			$backup_provider = $providers['Two_Factor_Backup_Codes'];
			// Check if user has backup codes already
			$codes_count = $backup_provider::codes_remaining_for_user( $user );
			if ( $codes_count == 0 ) {
				// Generate new codes if none exist
				$backup_codes = $backup_provider->generate_codes( $user );
				// Store in session immediately
				$_SESSION['two_factor_backup_codes'] = $backup_codes;
			} else {
				// User already has backup codes but they're not in session
				// This means they were already generated and can't be displayed again
				$codes_already_exist = true;
			}
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
		<?php elseif ( isset( $codes_already_exist ) && $codes_already_exist ): ?>
			<div class="two-factor-message info">
				<p><?php _e( 'Backup codes have already been generated for your account. For security reasons, they can only be displayed once when first created.', 'two-factor' ); ?></p>
				<p><?php _e( 'If you need new backup codes, you can generate them from your user profile settings.', 'two-factor' ); ?></p>
			</div>
		<?php else: ?>
			<div class="two-factor-message error">
				<p><?php _e( 'Unable to generate backup codes. You can generate them later from your profile.', 'two-factor' ); ?></p>
			</div>
		<?php endif; ?>

		<form method="post" action="" class="two-factor-form">
			<?php wp_nonce_field( 'two_factor_setup_backup', '_wpnonce' ); ?>
			<input type="hidden" name="backup_codes_acknowledged" value="1" />
			
			<?php if ( ! empty( $backup_codes ) ): ?>
				<div class="form-field">
					<label>
						<input type="checkbox" name="codes_saved" required />
						<?php _e( 'I have saved these backup codes in a secure location', 'two-factor' ); ?>
					</label>
				</div>
			<?php elseif ( isset( $codes_already_exist ) && $codes_already_exist ): ?>
				<div class="form-field">
					<label>
						<input type="checkbox" name="codes_acknowledged" required />
						<?php _e( 'I understand that backup codes have been generated for my account', 'two-factor' ); ?>
					</label>
				</div>
			<?php endif; ?>
			
			<p>
				<input type="submit" 
					   class="btn btn-primary btn-full-width" 
					   value="<?php esc_attr_e( 'Complete Setup', 'two-factor' ); ?>" />
			</p>
		</form>
	</div>

	<?php if ( ! empty( $backup_codes ) ): ?>
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
	<?php endif; ?>
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
			font-size: 1.2rem !important;
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
