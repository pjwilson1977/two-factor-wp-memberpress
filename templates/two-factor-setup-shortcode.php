<?php
/**
 * Two Factor Setup Shortcode Template
 */

$current_user = wp_get_current_user();
?>

<div class="two-factor-setup-shortcode">
	<h3><?php _e( 'Set Up Two-Factor Authentication', 'two-factor' ); ?></h3>
	
	<?php if ( Two_Factor_Core::is_user_using_two_factor( $current_user->ID ) ): ?>
		<p><?php _e( 'Two-factor authentication is already configured for your account.', 'two-factor' ); ?></p>
		
		<h4><?php _e( 'Manage Your Settings', 'two-factor' ); ?></h4>
		<ul>
			<li><a href="<?php echo esc_url( admin_url( 'profile.php#two-factor-options' ) ); ?>"><?php _e( 'Manage Two-Factor Settings', 'two-factor' ); ?></a></li>
		</ul>
		
	<?php else: ?>
		<p><?php _e( 'Protect your account by enabling two-factor authentication. This adds an extra layer of security by requiring a code from your phone in addition to your password.', 'two-factor' ); ?></p>
		
		<a href="<?php echo esc_url( add_query_arg( 'two_factor_setup', '1', home_url() ) ); ?>" class="button button-primary">
			<?php _e( 'Set Up Two-Factor Authentication', 'two-factor' ); ?>
		</a>
	<?php endif; ?>
</div>

<style>
.two-factor-setup-shortcode {
	background: #f9f9f9;
	padding: 20px;
	border: 1px solid #ddd;
	border-radius: 5px;
	margin: 20px 0;
}

.two-factor-setup-shortcode h3 {
	margin-top: 0;
	color: #333;
}

.two-factor-setup-shortcode .button {
	display: inline-block;
	padding: 10px 20px;
	background: #0073aa;
	color: white;
	text-decoration: none;
	border-radius: 3px;
	border: none;
	cursor: pointer;
}

.two-factor-setup-shortcode .button:hover {
	background: #005a87;
	color: white;
}
</style>
