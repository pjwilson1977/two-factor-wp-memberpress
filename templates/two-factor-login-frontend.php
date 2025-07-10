<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?php _e( 'Two-Factor Authentication', 'two-factor' ); ?> | <?php bloginfo( 'name' ); ?></title>
	<?php wp_head(); ?>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			background: #f1f1f1;
			margin: 0;
			padding: 20px;
		}
		.two-factor-login-container {
			max-width: 400px;
			margin: 50px auto;
			background: white;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 2px 10px rgba(0,0,0,0.1);
		}
		.login-header {
			text-align: center;
			margin-bottom: 30px;
		}
		.login-header h1 {
			color: #333;
			margin-bottom: 10px;
		}
		.form-field {
			margin-bottom: 20px;
		}
		.form-field label {
			display: block;
			margin-bottom: 5px;
			font-weight: 600;
		}
		.form-field input[type="text"], .form-field input[type="password"] {
			width: 100%;
			padding: 12px;
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
			width: 100%;
			box-sizing: border-box;
		}
		.btn:hover {
			background: #005a87;
		}
		.btn-secondary {
			background: #666;
			margin-top: 10px;
		}
		.btn-secondary:hover {
			background: #555;
		}
		.error-message {
			background: #f8d7da;
			color: #721c24;
			padding: 10px;
			border: 1px solid #f5c6cb;
			border-radius: 4px;
			margin-bottom: 20px;
		}
		.provider-options {
			margin-top: 20px;
			padding-top: 20px;
			border-top: 1px solid #eee;
		}
		.provider-options h3 {
			margin-bottom: 15px;
			color: #555;
		}
		.provider-list {
			list-style: none;
			padding: 0;
			margin: 0;
		}
		.provider-list li {
			margin-bottom: 10px;
		}
		.provider-list a {
			display: block;
			padding: 10px;
			background: #f9f9f9;
			border: 1px solid #ddd;
			border-radius: 4px;
			text-decoration: none;
			color: #333;
		}
		.provider-list a:hover {
			background: #f0f0f0;
		}
		.backup-code-input {
			display: none;
		}
		.backup-code-input.show {
			display: block;
		}
	</style>
</head>
<body>
	<div class="two-factor-login-container">
		<div class="login-header">
			<h1><?php _e( 'Two-Factor Authentication', 'two-factor' ); ?></h1>
			<p><?php printf( __( 'Welcome back, %s!', 'two-factor' ), esc_html( $user->display_name ) ); ?></p>
			<p><?php _e( 'Please enter your authentication code to complete login.', 'two-factor' ); ?></p>
		</div>

		<?php if ( ! empty( $error_msg ) ): ?>
			<div class="error-message">
				<?php echo esc_html( $error_msg ); ?>
			</div>
		<?php endif; ?>

		<?php
		$provider = $primary_provider;
		if ( $provider ):
		?>
		<form method="post" action="">
			<input type="hidden" name="provider" value="<?php echo esc_attr( get_class( $provider ) ); ?>" />
			<input type="hidden" name="wp-auth-id" value="<?php echo esc_attr( $user->ID ); ?>" />
			<input type="hidden" name="wp-auth-nonce" value="<?php echo esc_attr( $login_nonce ); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
			<input type="hidden" name="rememberme" value="<?php echo esc_attr( $rememberme ); ?>" />

			<div class="form-field">
				<label for="authcode"><?php echo esc_html( $provider->get_label() ); ?></label>
				<?php $provider->authentication_page( $user ); ?>
			</div>

			<button type="submit" class="btn"><?php _e( 'Verify', 'two-factor' ); ?></button>
		</form>
		<?php endif; ?>

		<?php if ( count( $available_providers ) > 1 || $backup_available ): ?>
		<div class="provider-options">
			<h3><?php _e( 'Alternative Methods', 'two-factor' ); ?></h3>

			<?php if ( $backup_available ): ?>
			<div class="backup-code-toggle">
				<a href="#" onclick="toggleBackupCode(); return false;"><?php _e( 'Use a backup code', 'two-factor' ); ?></a>
			</div>

			<div class="backup-code-input" id="backup-code-form">
				<form method="post" action="">
					<input type="hidden" name="provider" value="Two_Factor_Backup_Codes" />
					<input type="hidden" name="wp-auth-id" value="<?php echo esc_attr( $user->ID ); ?>" />
					<input type="hidden" name="wp-auth-nonce" value="<?php echo esc_attr( $login_nonce ); ?>" />
					<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
					<input type="hidden" name="rememberme" value="<?php echo esc_attr( $rememberme ); ?>" />

					<div class="form-field">
						<label for="backup-code"><?php _e( 'Backup Code', 'two-factor' ); ?></label>
						<input type="text" name="two-factor-backup-code" id="backup-code" placeholder="<?php _e( 'Enter backup code', 'two-factor' ); ?>" />
					</div>
					<button type="submit" class="btn"><?php _e( 'Verify Backup Code', 'two-factor' ); ?></button>
				</form>
			</div>
			<?php endif; ?>

			<?php if ( count( $available_providers ) > 1 ): ?>
			<ul class="provider-list">
				<?php foreach ( $available_providers as $available_provider ): ?>
					<?php if ( get_class( $available_provider ) !== get_class( $provider ) ): ?>
					<li>
						<a href="<?php echo esc_url( add_query_arg( 'provider', get_class( $available_provider ) ) ); ?>">
							<?php echo esc_html( $available_provider->get_label() ); ?>
						</a>
					</li>
					<?php endif; ?>
				<?php endforeach; ?>
			</ul>
			<?php endif; ?>
		</div>
		<?php endif; ?>
	</div>

	<script>
		function toggleBackupCode() {
			var form = document.getElementById('backup-code-form');
			if (form.classList.contains('show')) {
				form.classList.remove('show');
			} else {
				form.classList.add('show');
			}
		}
	</script>

	<?php wp_footer(); ?>
</body>
</html>
