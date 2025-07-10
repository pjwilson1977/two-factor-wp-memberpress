<?php
/**
 * MemberPress Integration Class for Two Factor Authentication
 *
 * @package Two_Factor
 */

/**
 * Class for handling MemberPress-specific two-factor authentication integration.
 *
 * @since 0.14.0-mp.1
 */
class Two_Factor_MemberPress {

	/**
	 * User meta key to track if user needs to setup 2FA
	 *
	 * @var string
	 */
	const USER_NEEDS_2FA_SETUP_KEY = '_two_factor_needs_setup';

	/**
	 * User meta key to track if user has been forced to setup 2FA
	 *
	 * @var string
	 */
	const USER_2FA_SETUP_FORCED_KEY = '_two_factor_setup_forced';

	/**
	 * Option key for plugin settings
	 *
	 * @var string
	 */
	const SETTINGS_KEY = 'two_factor_memberpress_settings';

	/**
	 * Initialize the MemberPress integration
	 */
	public static function init() {
		// Add debugging
		error_log( 'Two_Factor_MemberPress::init() called' );
		
		// Hook into WordPress login process
		add_action( 'wp_login', array( __CLASS__, 'handle_user_login' ), 5, 2 );
		error_log( 'Added wp_login hook' );
		
		// Hook into MemberPress login process
		add_action( 'mepr-event-login', array( __CLASS__, 'handle_memberpress_login' ), 5, 1 );
		
		// Add frontend 2FA setup handling
		add_action( 'init', array( __CLASS__, 'handle_frontend_2fa_setup' ) );
		
		// Add shortcode for 2FA setup
		add_shortcode( 'two_factor_setup', array( __CLASS__, 'two_factor_setup_shortcode' ) );
		
		// Admin settings
		add_action( 'admin_menu', array( __CLASS__, 'add_admin_menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
		
		// Mark new users as needing 2FA setup
		add_action( 'user_register', array( __CLASS__, 'mark_new_user_needs_2fa' ) );
		
		// Plugin activation hook
		add_action( 'activate_' . plugin_basename( TWO_FACTOR_DIR . 'two-factor.php' ), array( __CLASS__, 'on_plugin_activation' ) );
		
		// Filter available providers based on settings
		add_filter( 'two_factor_providers', array( __CLASS__, 'filter_allowed_providers' ) );
		
		// Handle frontend 2FA validation
		add_action( 'init', array( __CLASS__, 'handle_frontend_2fa_validation' ) );
		
		// Enqueue scripts and styles
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue_frontend_assets' ) );
		
		// Hook into all login attempts for debugging
		add_action( 'wp_authenticate', array( __CLASS__, 'debug_login_attempt' ), 1, 2 );
		add_action( 'authenticate', array( __CLASS__, 'debug_authenticate' ), 1, 3 );
	}
	
	/**
	 * Debug login attempt
	 */
	public static function debug_login_attempt( $username, $password ) {
		error_log( 'wp_authenticate hook fired for username: ' . $username );
	}
	
	/**
	 * Debug authenticate
	 */
	public static function debug_authenticate( $user, $username, $password ) {
		error_log( 'authenticate hook fired for username: ' . $username );
		if ( is_wp_error( $user ) ) {
			error_log( 'Authentication error: ' . $user->get_error_message() );
		} elseif ( $user instanceof WP_User ) {
			error_log( 'Authentication successful for user ID: ' . $user->ID );
		}
		return $user;
	}

	/**
	 * Handle user login and redirect to 2FA setup if needed
	 *
	 * @param string  $user_login Username
	 * @param WP_User $user       User object
	 */
	public static function handle_user_login( $user_login, $user ) {
		// Add debugging
		error_log( 'handle_user_login called for user: ' . $user_login . ' (ID: ' . $user->ID . ')' );
		error_log( 'is_admin(): ' . ( is_admin() ? 'Yes' : 'No' ) );
		error_log( 'Current URL: ' . ( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : 'unknown' ) );
		
		// Check if user needs 2FA setup
		$needs_setup = self::user_needs_2fa_setup( $user->ID );
		error_log( 'User needs 2FA setup: ' . ( $needs_setup ? 'Yes' : 'No' ) );
		
		// Debug user 2FA status
		$has_2fa = Two_Factor_Core::is_user_using_two_factor( $user->ID );
		error_log( 'User has 2FA enabled: ' . ( $has_2fa ? 'Yes' : 'No' ) );
		
		$needs_setup_meta = get_user_meta( $user->ID, self::USER_NEEDS_2FA_SETUP_KEY, true );
		error_log( 'User needs setup meta value: ' . $needs_setup_meta );
		
		// If user needs 2FA setup, redirect to setup
		if ( $needs_setup ) {
			error_log( 'Redirecting user to 2FA setup' );
			// Prevent normal login flow
			wp_clear_auth_cookie();
			
			// Store user info in session for 2FA setup
			self::store_user_for_2fa_setup( $user );
			
			// Redirect to 2FA setup page
			self::redirect_to_2fa_setup();
			exit;
		}
		
		// If user has 2FA enabled, require 2FA authentication
		if ( $has_2fa ) {
			error_log( 'User has 2FA enabled, requiring 2FA authentication' );
			// Prevent normal login flow
			wp_clear_auth_cookie();
			
			// Store user info for 2FA login with redirect URL
			$redirect_to = '';
			if ( isset( $_POST['redirect_to'] ) && ! empty( $_POST['redirect_to'] ) ) {
				$redirect_to = sanitize_url( $_POST['redirect_to'] );
			} elseif ( isset( $_GET['redirect_to'] ) && ! empty( $_GET['redirect_to'] ) ) {
				$redirect_to = sanitize_url( $_GET['redirect_to'] );
			} else {
				$redirect_to = self::get_post_login_redirect_url( $user );
			}
			
			error_log( 'Storing redirect URL: ' . $redirect_to );
			
			// Store user info for 2FA login
			if ( ! session_id() ) {
				session_start();
			}
			$_SESSION['two_factor_login_user_id'] = $user->ID;
			$_SESSION['two_factor_login_timestamp'] = time();
			$_SESSION['two_factor_login_redirect'] = $redirect_to;
			
			// Redirect to frontend 2FA login
			self::redirect_to_frontend_2fa_login();
			exit;
		}
		
		error_log( 'No 2FA action needed for user' );
	}

	/**
	 * Handle MemberPress login events
	 *
	 * @param object $event MemberPress event object
	 */
	public static function handle_memberpress_login( $event ) {
		if ( isset( $event->data ) && isset( $event->data['user'] ) ) {
			$user = $event->data['user'];
			if ( $user instanceof WP_User ) {
				self::handle_user_login( $user->user_login, $user );
			}
		}
	}

	/**
	 * Check if user needs to setup 2FA
	 *
	 * @param int $user_id User ID
	 * @return bool
	 */
	public static function user_needs_2fa_setup( $user_id ) {
		// Clean up any inconsistent state first
		self::cleanup_user_2fa_state( $user_id );
		
		$settings = self::get_settings();
		
		// If 2FA is not forced globally, return false
		if ( ! isset( $settings['force_2fa'] ) || ! $settings['force_2fa'] ) {
			error_log( "2FA not forced globally for user $user_id" );
			return false;
		}
		
		// Check if user role is required to have 2FA
		$user = get_user_by( 'ID', $user_id );
		if ( ! $user ) {
			error_log( "User $user_id not found" );
			return false;
		}
		
		$required_roles = isset( $settings['required_roles'] ) ? $settings['required_roles'] : array();
		if ( ! empty( $required_roles ) ) {
			$user_roles = $user->roles;
			$role_match = array_intersect( $user_roles, $required_roles );
			if ( empty( $role_match ) ) {
				error_log( "User $user_id role not in required roles: " . print_r( $user_roles, true ) );
				return false;
			}
		}
		
		// Check if user has been marked as needing setup
		$needs_setup = get_user_meta( $user_id, self::USER_NEEDS_2FA_SETUP_KEY, true );
		$has_2fa = Two_Factor_Core::is_user_using_two_factor( $user_id );
		
		error_log( "User $user_id: needs_setup=$needs_setup, has_2fa=" . ( $has_2fa ? 'Yes' : 'No' ) );
		
		// Only return true if user needs setup AND doesn't have 2FA configured
		$result = ! empty( $needs_setup ) && ! $has_2fa;
		error_log( "user_needs_2fa_setup($user_id) returning: " . ( $result ? 'true' : 'false' ) );
		
		return $result;
	}

	/**
	 * Mark user as needing 2FA setup
	 *
	 * @param int $user_id User ID
	 */
	public static function mark_user_needs_2fa_setup( $user_id ) {
		update_user_meta( $user_id, self::USER_NEEDS_2FA_SETUP_KEY, true );
	}

	/**
	 * Mark new user as needing 2FA setup
	 *
	 * @param int $user_id User ID
	 */
	public static function mark_new_user_needs_2fa( $user_id ) {
		$settings = self::get_settings();
		if ( isset( $settings['force_2fa'] ) && $settings['force_2fa'] ) {
			self::mark_user_needs_2fa_setup( $user_id );
		}
	}

	/**
	 * Store user info for 2FA setup process
	 *
	 * @param WP_User $user User object
	 */
	private static function store_user_for_2fa_setup( $user ) {
		if ( ! session_id() ) {
			session_start();
		}
		$_SESSION['two_factor_setup_user_id'] = $user->ID;
		$_SESSION['two_factor_setup_timestamp'] = time();
	}

	/**
	 * Store user info for 2FA login process
	 *
	 * @param WP_User $user User object
	 */
	private static function store_user_for_2fa_login( $user ) {
		if ( ! session_id() ) {
			session_start();
		}
		$_SESSION['two_factor_login_user_id'] = $user->ID;
		$_SESSION['two_factor_login_timestamp'] = time();
		$_SESSION['two_factor_login_redirect'] = isset( $_POST['redirect_to'] ) ? $_POST['redirect_to'] : home_url();
	}

	/**
	 * Get stored user for 2FA setup
	 *
	 * @return WP_User|null
	 */
	private static function get_stored_user_for_2fa_setup() {
		if ( ! session_id() ) {
			session_start();
		}
		
		if ( ! isset( $_SESSION['two_factor_setup_user_id'] ) || ! isset( $_SESSION['two_factor_setup_timestamp'] ) ) {
			return null;
		}
		
		// Check if session is still valid (30 minutes)
		if ( time() - $_SESSION['two_factor_setup_timestamp'] > 1800 ) {
			unset( $_SESSION['two_factor_setup_user_id'] );
			unset( $_SESSION['two_factor_setup_timestamp'] );
			return null;
		}
		
		return get_user_by( 'ID', $_SESSION['two_factor_setup_user_id'] );
	}

	/**
	 * Get stored user for 2FA login
	 *
	 * @return WP_User|null
	 */
	private static function get_stored_user_for_2fa_login() {
		if ( ! session_id() ) {
			session_start();
		}
		
		error_log( 'get_stored_user_for_2fa_login: Session ID = ' . session_id() );
		error_log( 'Session data: ' . print_r( $_SESSION, true ) );
		
		if ( ! isset( $_SESSION['two_factor_login_user_id'] ) || ! isset( $_SESSION['two_factor_login_timestamp'] ) ) {
			error_log( 'No 2FA login session data found' );
			return null;
		}
		
		// Check if session is still valid (30 minutes)
		$time_diff = time() - $_SESSION['two_factor_login_timestamp'];
		if ( $time_diff > 1800 ) {
			error_log( 'Session expired: ' . $time_diff . ' seconds old' );
			unset( $_SESSION['two_factor_login_user_id'] );
			unset( $_SESSION['two_factor_login_timestamp'] );
			unset( $_SESSION['two_factor_login_redirect'] );
			return null;
		}
		
		$user = get_user_by( 'ID', $_SESSION['two_factor_login_user_id'] );
		error_log( 'Retrieved user from session: ' . ( $user ? $user->user_login : 'null' ) );
		
		return $user;
	}

	/**
	 * Clear stored user for 2FA setup
	 */
	private static function clear_stored_user_for_2fa_setup() {
		if ( ! session_id() ) {
			session_start();
		}
		unset( $_SESSION['two_factor_setup_user_id'] );
		unset( $_SESSION['two_factor_setup_timestamp'] );
	}

	/**
	 * Clear stored user for 2FA login
	 */
	private static function clear_stored_user_for_2fa_login() {
		if ( ! session_id() ) {
			session_start();
		}
		unset( $_SESSION['two_factor_login_user_id'] );
		unset( $_SESSION['two_factor_login_timestamp'] );
		unset( $_SESSION['two_factor_login_redirect'] );
	}

	/**
	 * Redirect to 2FA setup page
	 */
	private static function redirect_to_2fa_setup() {
		$setup_url = add_query_arg( 'two_factor_setup', '1', home_url() );
		wp_redirect( $setup_url );
	}

	/**
	 * Redirect to frontend 2FA login page
	 */
	private static function redirect_to_frontend_2fa_login() {
		$login_url = add_query_arg( 'two_factor_login', '1', home_url() );
		wp_redirect( $login_url );
	}

	/**
	 * Handle frontend 2FA setup process
	 */
	public static function handle_frontend_2fa_setup() {
		// Add debugging
		error_log( 'handle_frontend_2fa_setup called. REQUEST_METHOD: ' . $_SERVER['REQUEST_METHOD'] );
		error_log( 'POST data: ' . print_r( $_POST, true ) );
		error_log( 'GET data: ' . print_r( $_GET, true ) );
		
		// Handle 2FA setup
		if ( isset( $_GET['two_factor_setup'] ) && $_GET['two_factor_setup'] === '1' ) {
			error_log( 'Handling 2FA setup request' );
			
			// Handle POST form submissions (verification, backup codes, etc.)
			if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
				error_log( 'Processing POST request for 2FA setup' );
				self::process_2fa_setup_form();
				return; // Important: return after processing to prevent further execution
			}
			
			// Handle GET with setup confirmation (user clicked "I've Added the Account to My App")
			if ( isset( $_GET['setup_confirmed'] ) && $_GET['setup_confirmed'] === '1' ) {
				error_log( 'User confirmed setup, advancing to verify step' );
				// User confirmed they've added the account, advance to verification
				// The step=verify is already in the URL, so just continue to display
			}
			
			// Display 2FA setup page
			add_action( 'wp', array( __CLASS__, 'display_2fa_setup_page' ), 1 );
			return;
		}
		
		// Handle 2FA login
		if ( isset( $_GET['two_factor_login'] ) && $_GET['two_factor_login'] === '1' ) {
			error_log( 'Handling 2FA login request' );
			// Display 2FA login page
			add_action( 'wp', array( __CLASS__, 'display_2fa_login_page' ), 1 );
			return;
		}
	}

	/**
	 * Process 2FA setup form submission
	 */
	private static function process_2fa_setup_form() {
		error_log( 'process_2fa_setup_form started' );
		
		$step = isset( $_GET['step'] ) ? sanitize_text_field( $_GET['step'] ) : 'setup';
		error_log( 'Processing step: ' . $step );
		
		// Different nonce for different steps
		$nonce_action = '';
		switch ( $step ) {
			case 'verify':
				$nonce_action = 'two_factor_setup_verify';
				break;
			case 'backup':
				$nonce_action = 'two_factor_setup_backup';
				break;
			default:
				$nonce_action = 'two_factor_setup_' . $step;
				break;
		}
		
		// Check nonce
		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], $nonce_action ) ) {
			error_log( 'Nonce verification failed for action: ' . $nonce_action );
			wp_die( __( 'Security check failed. Please try again.', 'two-factor' ) );
		}

		$user = self::get_stored_user_for_2fa_setup();
		if ( ! $user ) {
			error_log( 'No stored user found for 2FA setup' );
			wp_redirect( home_url() );
			exit;
		}

		$step = isset( $_GET['step'] ) ? sanitize_text_field( $_GET['step'] ) : 'setup';
		error_log( 'Processing step: ' . $step );
		
		// Handle verify step - fix field name here
		if ( $step === 'verify' && isset( $_POST['totp_code'] ) ) {
			$authcode = sanitize_text_field( $_POST['totp_code'] );
			error_log( 'Received TOTP code: ' . $authcode . ' for user: ' . $user->user_login );
			
			$secret = get_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, true );
			error_log( 'User secret exists: ' . ( $secret ? 'Yes' : 'No' ) );
			error_log( 'Secret (first 10 chars): ' . ( $secret ? substr( $secret, 0, 10 ) . '...' : 'N/A' ) );
			
			if ( empty( $secret ) ) {
				error_log( 'ERROR: No secret found for user ' . $user->ID );
				wp_redirect( add_query_arg( array( 'two_factor_setup' => '1', 'step' => 'setup', 'error' => 'no_secret' ), home_url() ) );
				exit;
			}
			
			$providers = Two_Factor_Core::get_providers();
			if ( ! isset( $providers['Two_Factor_Totp'] ) ) {
				error_log( 'ERROR: TOTP provider not available during verification' );
				wp_redirect( add_query_arg( array( 'two_factor_setup' => '1', 'step' => 'verify', 'error' => 'provider_error' ), home_url() ) );
				exit;
			}
			
			$totp_provider = $providers['Two_Factor_Totp'];
			
			// Add detailed TOTP validation debugging
			$current_time = time();
			$time_step = 30; // TOTP time step in seconds
			$current_window = floor( $current_time / $time_step );
			
			error_log( 'Current time: ' . $current_time );
			error_log( 'Current TOTP window: ' . $current_window );
			error_log( 'User ID: ' . $user->ID );
			
			// Generate expected codes for debugging
			for ( $i = -2; $i <= 2; $i++ ) {
				$test_window = $current_window + $i;
				$expected_code = $totp_provider->calc_totp( $secret, $test_window );
				error_log( 'Expected code for window ' . $test_window . ' (offset ' . $i . '): ' . $expected_code );
			}
			
			// Test validation
			$is_valid = $totp_provider->is_valid_authcode( $secret, $authcode );
			error_log( 'TOTP validation result: ' . ( $is_valid ? 'VALID' : 'INVALID' ) );
			
			if ( $is_valid ) {
				error_log( 'TOTP code validated successfully for user ' . $user->user_login );
				
				// Code is valid, enable TOTP for user
				Two_Factor_Core::enable_provider_for_user( $user->ID, 'Two_Factor_Totp' );
				error_log( 'Enabled TOTP provider for user ' . $user->ID );
				
				// Set as primary provider
				update_user_meta( $user->ID, Two_Factor_Core::PROVIDER_USER_META_KEY, 'Two_Factor_Totp' );
				error_log( 'Set TOTP as primary provider for user ' . $user->ID );
				
				// Generate backup codes if provider exists
				$providers = Two_Factor_Core::get_providers();
				if ( isset( $providers['Two_Factor_Backup_Codes'] ) ) {
					$backup_provider = $providers['Two_Factor_Backup_Codes'];
					$backup_codes = $backup_provider->generate_codes( $user );
					error_log( 'Generated backup codes for user ' . $user->ID . ': ' . count( $backup_codes ) . ' codes' );
				} else {
					error_log( 'Backup codes provider not available' );
				}
				
				error_log( 'Redirecting to backup codes step' );
				// Redirect to backup codes step
				wp_redirect( add_query_arg( array( 'two_factor_setup' => '1', 'step' => 'backup' ), home_url() ) );
				exit;
			} else {
				error_log( 'TOTP code validation failed for code: ' . $authcode . ' (user: ' . $user->user_login . ')' );
				// Invalid code
				wp_redirect( add_query_arg( array( 'two_factor_setup' => '1', 'step' => 'verify', 'error' => 'invalid_code' ), home_url() ) );
				exit;
			}
		}
		
		// Handle backup codes step completion
		if ( $step === 'backup' && isset( $_POST['backup_codes_acknowledged'] ) ) {
			error_log( 'Processing backup codes acknowledgment' );
			
			// Mark setup as complete
			delete_user_meta( $user->ID, self::USER_NEEDS_2FA_SETUP_KEY );
			self::clear_stored_user_for_2fa_setup();
			
			// Log the user in
			wp_set_current_user( $user->ID );
			wp_set_auth_cookie( $user->ID );
			
			// Redirect to success or intended destination
			$redirect_to = self::get_post_login_redirect_url( $user );
			error_log( 'Setup complete, redirecting to: ' . $redirect_to );
			
			wp_redirect( $redirect_to );
			exit;
		}
		
		error_log( 'No matching conditions in process_2fa_setup_form' );
	}

	/**
	 * Setup TOTP for user
	 *
	 * @param WP_User $user User object
	 */
	private static function setup_totp_for_user( $user ) {
		$totp_provider = Two_Factor_Core::get_providers()['Two_Factor_Totp'];
		if ( $totp_provider ) {
			// Generate new secret
			$secret = $totp_provider->generate_key();
			update_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, $secret );
			
			// Enable TOTP provider
			$enabled_providers = get_user_meta( $user->ID, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, true );
			if ( ! is_array( $enabled_providers ) ) {
				$enabled_providers = array();
			}
			if ( ! in_array( 'Two_Factor_Totp', $enabled_providers ) ) {
				$enabled_providers[] = 'Two_Factor_Totp';
				update_user_meta( $user->ID, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, $enabled_providers );
			}
			
			// Set as primary provider
			update_user_meta( $user->ID, Two_Factor_Core::PROVIDER_USER_META_KEY, 'Two_Factor_Totp' );
		}
	}

	/**
	 * Verify TOTP setup
	 *
	 * @param WP_User $user User object
	 */
	private static function verify_totp_setup( $user ) {
		if ( ! isset( $_POST['totp_code'] ) ) {
			return;
		}
		
		$totp_provider = Two_Factor_Core::get_providers()['Two_Factor_Totp'];
		$code = sanitize_text_field( $_POST['totp_code'] );
		
		if ( $totp_provider && $totp_provider->validate_authentication( $user, array( 'two-factor-totp-authcode' => $code ) ) ) {
			// TOTP verified successfully
			update_user_meta( $user->ID, '_two_factor_totp_verified', true );
			
			// Redirect to backup codes generation
			$redirect_url = add_query_arg( array(
				'two_factor_setup' => '1',
				'step' => 'backup_codes'
			), home_url() );
			wp_redirect( $redirect_url );
			exit;
		} else {
			// Invalid code
			wp_redirect( add_query_arg( array(
				'two_factor_setup' => '1',
				'step' => 'verify',
				'error' => 'invalid_code'
			), home_url() ) );
			exit;
		}
	}

	/**
	 * Generate backup codes for user
	 *
	 * @param WP_User $user User object
	 */
	private static function generate_backup_codes_for_user( $user ) {
		$backup_provider = Two_Factor_Core::get_providers()['Two_Factor_Backup_Codes'];
		if ( $backup_provider ) {
			// Enable backup codes provider
			$enabled_providers = get_user_meta( $user->ID, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, true );
			if ( ! is_array( $enabled_providers ) ) {
				$enabled_providers = array();
			}
			if ( ! in_array( 'Two_Factor_Backup_Codes', $enabled_providers ) ) {
				$enabled_providers[] = 'Two_Factor_Backup_Codes';
				update_user_meta( $user->ID, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, $enabled_providers );
			}
			
			// Generate backup codes
			$backup_provider->generate_codes( $user );
		}
	}

	/**
	 * Complete 2FA setup process
	 *
	 * @param WP_User $user User object
	 */
	private static function complete_2fa_setup( $user ) {
		// Mark user as no longer needing setup
		delete_user_meta( $user->ID, self::USER_NEEDS_2FA_SETUP_KEY );
		update_user_meta( $user->ID, self::USER_2FA_SETUP_FORCED_KEY, true );
		
		// Clear session
		self::clear_stored_user_for_2fa_setup();
		
		// Log the user in
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID );
		
		// Redirect to appropriate page
		$redirect_url = self::get_post_login_redirect_url( $user );
		wp_redirect( $redirect_url );
		exit;
	}

	/**
	 * Get post-login redirect URL
	 *
	 * @param WP_User $user User object
	 * @return string
	 */
	private static function get_post_login_redirect_url( $user ) {
		// Check for MemberPress redirect URL
		if ( class_exists( 'MeprOptions' ) ) {
			$mepr_options = MeprOptions::fetch();
			if ( ! empty( $mepr_options->login_redirect_url ) ) {
				return $mepr_options->login_redirect_url;
			}
		}
		
		// Default to admin or user profile
		if ( user_can( $user, 'manage_options' ) ) {
			return admin_url();
		} else {
			return home_url( '/account/' );
		}
	}

	/**
	 * Display 2FA setup page
	 */
	public static function display_2fa_setup_page() {
		$user = self::get_stored_user_for_2fa_setup();
		if ( ! $user ) {
			wp_die( __( 'Invalid session. Please try logging in again.', 'two-factor' ) );
		}
		
		error_log( 'Displaying 2FA setup page for user: ' . $user->user_login . ' (ID: ' . $user->ID . ')' );
		
		// Ensure TOTP secret is generated when user first accesses setup page
		$secret = get_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, true );
		if ( ! $secret ) {
			error_log( 'No TOTP secret found for user ' . $user->ID . ', generating new one' );
			$providers = Two_Factor_Core::get_providers();
			if ( isset( $providers['Two_Factor_Totp'] ) ) {
				$totp_provider = $providers['Two_Factor_Totp'];
				$secret = $totp_provider->generate_key();
				update_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, $secret );
				error_log( 'Generated and stored new TOTP secret for user ' . $user->ID );
			} else {
				error_log( 'ERROR: TOTP provider not available' );
			}
		} else {
			error_log( 'TOTP secret already exists for user ' . $user->ID );
		}
		
		// Get current step
		$step = isset( $_GET['step'] ) ? sanitize_text_field( $_GET['step'] ) : 'setup';
		error_log( 'Current setup step: ' . $step );
		
		// Display the setup page
		include_once TWO_FACTOR_DIR . 'templates/two-factor-setup-page.php';
		exit;
	}

	/**
	 * Display 2FA login page
	 */
	public static function display_2fa_login_page() {
		error_log( 'display_2fa_login_page called' );
		
		$user = self::get_stored_user_for_2fa_login();
		if ( ! $user ) {
			error_log( 'No stored user found for 2FA login, redirecting to home' );
			// Instead of dying, redirect back to login with an error
			wp_redirect( add_query_arg( array(
				'error' => 'session_expired',
				'message' => urlencode( 'Your session has expired. Please log in again.' )
			), wp_login_url() ) );
			exit;
		}
		
		error_log( 'Found stored user for 2FA login: ' . $user->user_login . ' (ID: ' . $user->ID . ')' );
		
		// Get provider from URL or use primary
		$provider_class = isset( $_GET['provider'] ) ? sanitize_text_field( $_GET['provider'] ) : null;
		$available_providers = Two_Factor_Core::get_available_providers_for_user( $user );
		$primary_provider = Two_Factor_Core::get_primary_provider_for_user( $user );
		
		error_log( 'Available providers: ' . print_r( array_keys( $available_providers ), true ) );
		error_log( 'Primary provider: ' . ( $primary_provider ? get_class( $primary_provider ) : 'None' ) );
		
		if ( $provider_class && isset( $available_providers[ $provider_class ] ) ) {
			$provider = $available_providers[ $provider_class ];
		} else {
			$provider = $primary_provider;
		}
		
		// Check for backup codes availability
		$backup_available = isset( $available_providers['Two_Factor_Backup_Codes'] );
		
		// Get login nonce
		$login_nonce_data = Two_Factor_Core::create_login_nonce( $user->ID );
		$login_nonce = $login_nonce_data ? $login_nonce_data['key'] : '';
		
		// Get redirect URL
		if ( ! session_id() ) {
			session_start();
		}
		$redirect_to = isset( $_SESSION['two_factor_login_redirect'] ) ? $_SESSION['two_factor_login_redirect'] : home_url();
		$rememberme = isset( $_POST['rememberme'] ) ? $_POST['rememberme'] : '';
		
		// Check for error message
		$error_msg = isset( $_GET['error'] ) ? self::get_error_message( $_GET['error'] ) : '';
		
		error_log( 'Displaying 2FA login page with provider: ' . ( $provider ? get_class( $provider ) : 'None' ) );
		
		// Display the login page
		include_once TWO_FACTOR_DIR . 'templates/two-factor-login-frontend.php';
		exit;
	}

	/**
	 * Get error message for display
	 *
	 * @param string $error_code Error code
	 * @return string
	 */
	private static function get_error_message( $error_code ) {
		switch ( $error_code ) {
			case 'invalid_code':
				return __( 'Invalid authentication code. Please try again.', 'two-factor' );
			case 'expired_session':
				return __( 'Your session has expired. Please log in again.', 'two-factor' );
			case 'invalid_backup_code':
				return __( 'Invalid backup code. Please try again.', 'two-factor' );
			default:
				return __( 'An error occurred. Please try again.', 'two-factor' );
		}
	}

	/**
	 * Handle frontend 2FA validation
	 */
	public static function handle_frontend_2fa_validation() {
		// Check if this is a 2FA validation request
		if ( ! isset( $_POST['wp-auth-id'] ) || ! isset( $_POST['wp-auth-nonce'] ) ) {
			return;
		}
		
		// Get user and verify nonce
		$user_id = absint( $_POST['wp-auth-id'] );
		$nonce = sanitize_text_field( $_POST['wp-auth-nonce'] );
		$provider_class = sanitize_text_field( $_POST['provider'] );
		
		$user = get_user_by( 'ID', $user_id );
		if ( ! $user ) {
			wp_redirect( add_query_arg( array(
				'two_factor_login' => '1',
				'error' => 'expired_session'
			), home_url() ) );
			exit;
		}
		
		// Verify nonce
		if ( ! Two_Factor_Core::verify_login_nonce( $user_id, $nonce ) ) {
			wp_redirect( add_query_arg( array(
				'two_factor_login' => '1',
				'error' => 'expired_session'
			), home_url() ) );
			exit;
		}
		
		// Get provider and validate
		$providers = Two_Factor_Core::get_available_providers_for_user( $user );
		if ( ! isset( $providers[ $provider_class ] ) ) {
			wp_redirect( add_query_arg( array(
				'two_factor_login' => '1',
				'error' => 'invalid_code'
			), home_url() ) );
			exit;
		}
		
		$provider = $providers[ $provider_class ];
		$result = $provider->validate_authentication( $user, $_POST );
		
		if ( $result ) {
			// Success - log in user
			self::complete_frontend_login( $user );
		} else {
			// Failed validation
			$error_code = ( $provider_class === 'Two_Factor_Backup_Codes' ) ? 'invalid_backup_code' : 'invalid_code';
			wp_redirect( add_query_arg( array(
				'two_factor_login' => '1',
				'error' => $error_code
			), home_url() ) );
			exit;
		}
	}

	/**
	 * Complete frontend login after successful 2FA
	 *
	 * @param WP_User $user User object
	 */
	private static function complete_frontend_login( $user ) {
		// Clear 2FA login session
		if ( ! session_id() ) {
			session_start();
		}
		$redirect_to = isset( $_SESSION['two_factor_login_redirect'] ) ? $_SESSION['two_factor_login_redirect'] : home_url();
		self::clear_stored_user_for_2fa_login();
		
		// Set authentication cookies
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, ! empty( $_POST['rememberme'] ) );
		
		// Redirect to intended page
		wp_redirect( $redirect_to );
		exit;
	}

	/**
	 * Two Factor setup shortcode
	 *
	 * @param array $atts Shortcode attributes
	 * @return string
	 */
	public static function two_factor_setup_shortcode( $atts ) {
		if ( ! is_user_logged_in() ) {
			return '<p>' . __( 'You must be logged in to access this page.', 'two-factor' ) . '</p>';
		}
		
		$user = wp_get_current_user();
		
		if ( ! self::user_needs_2fa_setup( $user->ID ) ) {
			return '<p>' . __( 'Two-factor authentication is already configured for your account.', 'two-factor' ) . '</p>';
		}
		
		ob_start();
		include_once TWO_FACTOR_DIR . 'templates/two-factor-setup-shortcode.php';
		return ob_get_clean();
	}

	/**
	 * Add admin menu
	 */
	public static function add_admin_menu() {
		add_options_page(
			__( 'Two Factor MemberPress Settings', 'two-factor' ),
			__( 'Two Factor MP', 'two-factor' ),
			'manage_options',
			'two-factor-memberpress',
			array( __CLASS__, 'admin_page' )
		);
	}

	/**
	 * Register settings
	 */
	public static function register_settings() {
		register_setting( 'two_factor_memberpress', self::SETTINGS_KEY );
		
		add_settings_section(
			'two_factor_memberpress_general',
			__( 'General Settings', 'two-factor' ),
			null,
			'two-factor-memberpress'
		);
		
		add_settings_field(
			'force_2fa',
			__( 'Force Two-Factor Authentication', 'two-factor' ),
			array( __CLASS__, 'force_2fa_field' ),
			'two-factor-memberpress',
			'two_factor_memberpress_general'
		);
		
		add_settings_field(
			'required_roles',
			__( 'Required User Roles', 'two-factor' ),
			array( __CLASS__, 'required_roles_field' ),
			'two-factor-memberpress',
			'two_factor_memberpress_general'
		);
		
		add_settings_field(
			'allowed_providers',
			__( 'Allowed Authentication Methods', 'two-factor' ),
			array( __CLASS__, 'allowed_providers_field' ),
			'two-factor-memberpress',
			'two_factor_memberpress_general'
		);
	}

	/**
	 * Force 2FA field
	 */
	public static function force_2fa_field() {
		$settings = self::get_settings();
		$checked = isset( $settings['force_2fa'] ) && $settings['force_2fa'];
		
		echo '<input type="checkbox" name="' . self::SETTINGS_KEY . '[force_2fa]" value="1" ' . checked( $checked, true, false ) . ' />';
		echo '<label>' . __( 'Force all users to set up two-factor authentication', 'two-factor' ) . '</label>';
	}

	/**
	 * Required roles field
	 */
	public static function required_roles_field() {
		$settings = self::get_settings();
		$required_roles = isset( $settings['required_roles'] ) ? $settings['required_roles'] : array();
		$roles = wp_roles()->roles;
		
		echo '<fieldset>';
		foreach ( $roles as $role_key => $role ) {
			$checked = in_array( $role_key, $required_roles );
			echo '<label><input type="checkbox" name="' . self::SETTINGS_KEY . '[required_roles][]" value="' . esc_attr( $role_key ) . '" ' . checked( $checked, true, false ) . ' /> ' . esc_html( $role['name'] ) . '</label><br/>';
		}
		echo '</fieldset>';
		echo '<p class="description">' . __( 'Select which user roles should be required to use two-factor authentication. Leave empty to apply to all users.', 'two-factor' ) . '</p>';
	}

	/**
	 * Allowed providers field
	 */
	public static function allowed_providers_field() {
		$settings = self::get_settings();
		$allowed_providers = isset( $settings['allowed_providers'] ) ? $settings['allowed_providers'] : array_keys( Two_Factor_Core::get_providers() );
		$providers = Two_Factor_Core::get_providers();
		
		echo '<fieldset>';
		foreach ( $providers as $provider_key => $provider ) {
			$checked = in_array( $provider_key, $allowed_providers );
			echo '<label><input type="checkbox" name="' . self::SETTINGS_KEY . '[allowed_providers][]" value="' . esc_attr( $provider_key ) . '" ' . checked( $checked, true, false ) . ' /> ' . esc_html( $provider->get_label() ) . '</label><br/>';
		}
		echo '</fieldset>';
		echo '<p class="description">' . __( 'Select which two-factor authentication methods users are allowed to use.', 'two-factor' ) . '</p>';
	}

	/**
	 * Admin page
	 */
	public static function admin_page() {
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<form method="post" action="options.php">
				<?php
				settings_fields( 'two_factor_memberpress' );
				do_settings_sections( 'two-factor-memberpress' );
				submit_button();
				?>
			</form>
			
			<h2><?php _e( 'Force Setup for Existing Users', 'two-factor' ); ?></h2>
			<p><?php _e( 'Click the button below to mark all existing users as needing to set up two-factor authentication on their next login.', 'two-factor' ); ?></p>
			<form method="post" action="">
				<?php wp_nonce_field( 'force_2fa_setup_all_users', 'force_2fa_nonce' ); ?>
				<input type="hidden" name="action" value="force_2fa_setup_all_users" />
				<?php submit_button( __( 'Force 2FA Setup for All Users', 'two-factor' ), 'secondary' ); ?>
			</form>
			
			<?php
			if ( isset( $_POST['action'] ) && $_POST['action'] === 'force_2fa_setup_all_users' && wp_verify_nonce( $_POST['force_2fa_nonce'], 'force_2fa_setup_all_users' ) ) {
				self::force_2fa_setup_for_all_users();
				echo '<div class="notice notice-success"><p>' . __( 'All users have been marked to set up two-factor authentication on their next login.', 'two-factor' ) . '</p></div>';
			}
			?>
		</div>
		<?php
	}

	/**
	 * Force 2FA setup for all existing users
	 */
	private static function force_2fa_setup_for_all_users() {
		$users = get_users( array( 'fields' => 'ID' ) );
		foreach ( $users as $user_id ) {
			if ( ! Two_Factor_Core::is_user_using_two_factor( $user_id ) ) {
				self::mark_user_needs_2fa_setup( $user_id );
			}
		}
	}

	/**
	 * Get plugin settings
	 *
	 * @return array
	 */
	public static function get_settings() {
		$defaults = array(
			'force_2fa' => true,
			'required_roles' => array(),
			'allowed_providers' => array( 'Two_Factor_Totp', 'Two_Factor_Email', 'Two_Factor_Backup_Codes' ),
		);
		
		$settings = get_option( self::SETTINGS_KEY, array() );
		return wp_parse_args( $settings, $defaults );
	}

	/**
	 * Handle plugin activation
	 */
	public static function on_plugin_activation() {
		// Set default settings
		if ( ! get_option( self::SETTINGS_KEY ) ) {
			update_option( self::SETTINGS_KEY, self::get_settings() );
		}
		
		// Mark all existing users as needing 2FA setup
		$users = get_users( array( 'fields' => 'ID' ) );
		foreach ( $users as $user_id ) {
			if ( ! Two_Factor_Core::is_user_using_two_factor( $user_id ) ) {
				self::mark_user_needs_2fa_setup( $user_id );
			}
		}
	}

	/**
	 * Filter allowed providers based on admin settings
	 *
	 * @param array $providers Array of provider keys and paths
	 * @return array Filtered providers
	 */
	public static function filter_allowed_providers( $providers ) {
		$settings = self::get_settings();
		$allowed_providers = isset( $settings['allowed_providers'] ) ? $settings['allowed_providers'] : array_keys( $providers );
		
		// Filter out providers that are not allowed
		foreach ( $providers as $provider_key => $provider_path ) {
			if ( ! in_array( $provider_key, $allowed_providers ) ) {
				unset( $providers[ $provider_key ] );
			}
		}
		
		return $providers;
	}

	/**
	 * Enqueue frontend assets for 2FA pages
	 */
	public static function enqueue_frontend_assets() {
		// Only enqueue on 2FA pages
		if ( isset( $_GET['two_factor_setup'] ) || isset( $_GET['two_factor_login'] ) ) {
			wp_enqueue_style(
				'two-factor-frontend',
				plugins_url( 'assets/two-factor-frontend.css', TWO_FACTOR_DIR . 'two-factor.php' ),
				array(),
				TWO_FACTOR_VERSION
			);
			
			wp_enqueue_script(
				'two-factor-frontend',
				plugins_url( 'assets/two-factor-frontend.js', TWO_FACTOR_DIR . 'two-factor.php' ),
				array(),
				TWO_FACTOR_VERSION,
				true
			);
		}
	}

	/**
	 * Debug helper to calculate TOTP code for a given time window
	 */
	private static function debug_calc_totp( $secret, $time_window ) {
		$totp_provider = Two_Factor_Core::get_providers()['Two_Factor_Totp'];
		
		// If calc_totp method exists, use it
		if ( method_exists( $totp_provider, 'calc_totp' ) ) {
			return $totp_provider->calc_totp( $secret, $time_window );
		}
		
		// Otherwise, calculate manually for debugging
		$time_bytes = pack( 'N*', 0 ) . pack( 'N*', $time_window );
		$hash = hash_hmac( 'sha1', $time_bytes, base32_decode( $secret ), true );
		$offset = ord( $hash[19] ) & 0xf;
		$code = (
			( ( ord( $hash[ $offset + 0 ] ) & 0x7f ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xff )
		) % pow( 10, 6 );
		
		return str_pad( $code, 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Clean up inconsistent user 2FA state
	 *
	 * @param int $user_id User ID
	 */
	public static function cleanup_user_2fa_state( $user_id ) {
		$has_2fa = Two_Factor_Core::is_user_using_two_factor( $user_id );
		$needs_setup = get_user_meta( $user_id, self::USER_NEEDS_2FA_SETUP_KEY, true );
		
		error_log( "Cleaning up 2FA state for user $user_id: has_2fa=" . ( $has_2fa ? 'Yes' : 'No' ) . ", needs_setup=$needs_setup" );
		
		// If user has 2FA configured but still marked as needing setup, clear the flag
		if ( $has_2fa && ! empty( $needs_setup ) ) {
			delete_user_meta( $user_id, self::USER_NEEDS_2FA_SETUP_KEY );
			error_log( "Cleared needs_setup flag for user $user_id who already has 2FA" );
		}
		
		// If user is forced to use 2FA but doesn't have it and isn't marked as needing setup, mark them
		$settings = self::get_settings();
		if ( isset( $settings['force_2fa'] ) && $settings['force_2fa'] && ! $has_2fa && empty( $needs_setup ) ) {
			self::mark_user_needs_2fa_setup( $user_id );
			error_log( "Marked user $user_id as needing 2FA setup" );
		}
	}
}
