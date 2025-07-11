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
		
		// Temporary admin function for testing
		add_action( 'admin_init', array( __CLASS__, 'reset_user_2fa_for_testing' ) );
		
		// Enqueue scripts and styles
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue_frontend_assets' ) );
		
		// Add to init() method
		add_action( 'init', array( __CLASS__, 'debug_frontend_2fa_login' ), 5 ); // Priority 5 to run early
		
		// Hook into all login attempts for debugging
		add_action( 'wp_authenticate', array( __CLASS__, 'debug_login_attempt' ), 1, 2 );
		add_action( 'authenticate', array( __CLASS__, 'debug_authenticate' ), 1, 3 );

		// debug email
		add_action( 'wp_mail', array( __CLASS__, 'debug_wp_mail' ), 10, 1 );
    	add_action( 'wp_mail_failed', array( __CLASS__, 'debug_wp_mail_failed' ), 10, 1 );
		
		// Admin user list actions
		add_filter( 'user_row_actions', array( __CLASS__, 'add_user_row_actions' ), 10, 2 );
		add_action( 'admin_init', array( __CLASS__, 'handle_admin_reset_2fa' ) );
		add_action( 'admin_notices', array( __CLASS__, 'admin_reset_2fa_notices' ) );
		
		// Add this to the init() method
		add_filter( 'two_factor_revalidate_time', array( __CLASS__, 'extend_grace_period_for_testing' ), 10, 3 );
		add_action('current_screen', array(__CLASS__, 'force_admin_2fa_access'), 1);
		
		// Comprehensive 2FA override
		add_action('init', array(__CLASS__, 'intercept_core_2fa_urls'), 1);
		add_action('login_form_revalidate_2fa', array(__CLASS__, 'override_core_2fa_action'), 1);
		add_action('login_form_validate_2fa', array(__CLASS__, 'override_core_2fa_action'), 1);
		add_filter('login_url', array(__CLASS__, 'override_login_url'), 10, 3);		
	}

	/**
	 * Debug frontend 2FA login handling
	 */
	public static function debug_frontend_2fa_login() {
		if ( ! isset( $_GET['two_factor_login'] ) ) {
			return;
		}
		
		error_log( '=== Frontend 2FA Login Debug ===' );
		error_log( 'GET parameters: ' . print_r( $_GET, true ) );
		error_log( 'POST parameters: ' . print_r( $_POST, true ) );
		
		// Fix: Ensure session is started before accessing $_SESSION
		if ( ! session_id() ) {
			session_start();
		}
		
		// Only log session data if session exists
		if ( isset( $_SESSION ) ) {
			error_log( 'SESSION data: ' . print_r( $_SESSION, true ) );
			
			// ADD THESE CHECKS
			if ( isset( $_SESSION['email_2fa_sent_1'] ) && !isset( $_SESSION['email_2fa_user_id'] ) ) {
				error_log( 'WARNING: Email 2FA timestamp found but no user ID - this indicates the session issue' );
			}
			
			if ( isset( $_SESSION['two_factor_login_user_id'] ) ) {
				error_log( 'User ID found in two_factor_login_user_id: ' . $_SESSION['two_factor_login_user_id'] );
			}
			
			if ( isset( $_SESSION['email_2fa_user_id'] ) ) {
				error_log( 'User ID found in email_2fa_user_id: ' . $_SESSION['email_2fa_user_id'] );
			}
		} else {
			error_log( 'SESSION data: No session available' );
		}
		
		// Check if provider switching is being handled
		if ( isset( $_GET['provider'] ) ) {
			error_log( 'Provider switching detected: ' . $_GET['provider'] );
			
			// Check if this provider exists
			$providers = Two_Factor_Core::get_providers();
			if ( isset( $providers[ $_GET['provider'] ] ) ) {
				error_log( 'Provider exists and is available' );
				$provider = $providers[ $_GET['provider'] ];
				error_log( 'Provider class: ' . get_class( $provider ) );
				error_log( 'Provider label: ' . $provider->get_label() );
			} else {
				error_log( 'ERROR: Provider not found in available providers' );
				error_log( 'Available providers: ' . print_r( array_keys( $providers ), true ) );
			}
		}
		
		// Check if user is in session
		if ( isset( $_SESSION['two_factor_login_user_id'] ) ) {
			$user_id = $_SESSION['two_factor_login_user_id'];
			error_log( 'User in session: ' . $user_id );
			
			$user = get_user_by( 'id', $user_id );
			if ( $user ) {
				error_log( 'User email: ' . $user->user_email );
				
				// Check enabled providers for this user
				$enabled_providers = Two_Factor_Core::get_enabled_providers_for_user( $user );
				error_log( 'Enabled providers for user: ' . print_r( array_keys( $enabled_providers ), true ) );
			}
		} else {
			error_log( 'ERROR: No user in session for 2FA login' );
		}
	}

	/**
	 * Debug wp_mail function calls with more detail
	 */
	public static function debug_wp_mail( $mail_data ) {
		// Check if this is a 2FA email
		$subject = isset( $mail_data['subject'] ) ? $mail_data['subject'] : '';
		$to = isset( $mail_data['to'] ) ? $mail_data['to'] : '';
		$message = isset( $mail_data['message'] ) ? $mail_data['message'] : '';
		
		error_log( '=== wp_mail DEBUG ===' );
		error_log( 'To: ' . $to );
		error_log( 'Subject: ' . $subject );
		error_log( 'Message length: ' . strlen( $message ) );
		error_log( 'Full mail data: ' . print_r( $mail_data, true ) );
		
		// Check if this looks like a 2FA email
		if ( strpos( $subject, 'verification' ) !== false || strpos( $subject, 'code' ) !== false || strpos( $message, 'verification' ) !== false ) {
			error_log( '*** This appears to be a 2FA email ***' );
			error_log( 'Message content: ' . $message );
		}
		
		return $mail_data;
	}

	/**
	 * Debug wp_mail failures
	 */
	public static function debug_wp_mail_failed( $wp_error ) {
		error_log( 'wp_mail failed: ' . $wp_error->get_error_message() );
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
		// Don't interfere with revalidation process
		if ( isset( $_GET['action'] ) && $_GET['action'] === 'revalidate_2fa' ) {
			error_log( 'Revalidation in progress - skipping custom 2FA handling' );
			return;
		}
		
		// Don't interfere with core 2FA validation
		if ( isset( $_GET['action'] ) && $_GET['action'] === 'validate_2fa' ) {
			error_log( 'Core 2FA validation in progress - skipping custom handling' );
			return;
		}
		
		// IMPORTANT: Don't interfere if this is a revalidation login
		// Check if user is already logged in AND this is the same user
		if ( is_user_logged_in() && get_current_user_id() === $user->ID ) {
			// Check if this was triggered by a revalidation process
			$session = Two_Factor_Core::get_current_user_session();
			if ( $session && isset( $session['two-factor-login'] ) ) {
				error_log( 'User already logged in with valid 2FA session - likely revalidation, skipping custom handling' );
				return;
			}
		}
		
		// Don't interfere with admin/wp-login.php based logins
		if ( is_admin() || ( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false ) ) {
			error_log( 'Admin or wp-login.php login detected - letting core handle 2FA' );
			return;
		}

		// Don't interfere with any core 2FA authentication posts
		if ( isset( $_POST['wp-auth-id'] ) || isset( $_POST['wp-auth-nonce'] ) ) {
			error_log( 'Core 2FA authentication POST detected - skipping custom handling' );
			return;
		}
		
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

			// ADD THIS LINE - Also store the user ID in the email session key format for consistency
			$_SESSION['email_2fa_user_id'] = $user->ID;
			
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
		
		// CHECK FOR REVALIDATION SCENARIO FIRST
		if ( isset( $_SESSION['email_2fa_user_id'] ) && is_user_logged_in() ) {
			$stored_user_id = $_SESSION['email_2fa_user_id'];
			$current_user = wp_get_current_user();
			
			// If the stored user matches the current logged-in user, this is likely revalidation
			if ( $current_user && $current_user->ID == $stored_user_id ) {
				error_log( 'Revalidation scenario detected - using current logged-in user: ' . $current_user->ID );
				
				// Set the login timestamp if not already set (for session validation)
				if ( ! isset( $_SESSION['two_factor_login_timestamp'] ) ) {
					$_SESSION['two_factor_login_timestamp'] = time();
					$_SESSION['two_factor_login_user_id'] = $current_user->ID;
					error_log( 'Set login timestamp for revalidation session' );
				}
				
				return $current_user;
			}
		}
		
		// ORIGINAL LOGIN FLOW CHECK
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
		
		// IMPORTANT: Don't interfere with ANY core 2FA processes
		if ( isset( $_GET['action'] ) && in_array( $_GET['action'], [ 'revalidate_2fa', 'validate_2fa' ] ) ) {
			error_log( 'Core 2FA action detected (' . $_GET['action'] . ') - letting core handle it' );
			return;
		}
		
		// Don't interfere if this is a revalidation POST
		if ( $_SERVER['REQUEST_METHOD'] === 'POST' && 
			 ( isset( $_POST['wp-auth-id'] ) || isset( $_POST['wp-auth-nonce'] ) || isset( $_POST['provider'] ) ) ) {
			error_log( 'Core 2FA POST detected - letting core handle it' );
			return;
		}
		
		// Don't interfere with wp-login.php based 2FA
		if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false ) {
			error_log( 'wp-login.php request detected - letting core handle it' );
			return;
		}
		
		// Only handle OUR specific 2FA setup process
		if ( isset( $_GET['two_factor_setup'] ) && $_GET['two_factor_setup'] === '1' ) {
			error_log( 'Handling custom 2FA setup request' );
			
			// Handle POST form submissions (verification, backup codes, etc.)
			if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
				error_log( 'Processing POST request for 2FA setup' );
				self::process_2fa_setup_form();
				return;
			}
			
			// Handle GET with setup confirmation
			if ( isset( $_GET['setup_confirmed'] ) && $_GET['setup_confirmed'] === '1' ) {
				error_log( 'User confirmed setup, advancing to verify step' );
			}
			
			// Display 2FA setup page
			add_action( 'wp', array( __CLASS__, 'display_2fa_setup_page' ), 1 );
			return;
		}
		
		// Only handle OUR specific 2FA login (not revalidation)
		if ( isset( $_GET['two_factor_login'] ) && $_GET['two_factor_login'] === '1' && 
			 !isset( $_GET['error'] ) ) // Don't handle error redirects from core
		{
			error_log( 'Handling custom 2FA login request' );
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
				
				// Generate backup codes and enable backup codes provider
				$providers = Two_Factor_Core::get_providers();
				if ( isset( $providers['Two_Factor_Backup_Codes'] ) ) {
					$backup_provider = $providers['Two_Factor_Backup_Codes'];
					
					// Enable backup codes provider for user
					Two_Factor_Core::enable_provider_for_user( $user->ID, 'Two_Factor_Backup_Codes' );
					error_log( 'Enabled backup codes provider for user ' . $user->ID );
					
					// Generate backup codes
					$backup_codes = $backup_provider->generate_codes( $user );
					error_log( 'Generated backup codes for user ' . $user->ID . ': ' . count( $backup_codes ) . ' codes' );
					
					// Store backup codes in session so they can be displayed to the user
					if ( ! session_id() ) {
						session_start();
					}
					$_SESSION['two_factor_backup_codes'] = $backup_codes;
					error_log( 'Stored backup codes in session for display' );
				} else {
					error_log( 'Backup codes provider not available' );
				}
				
				// Enable email 2FA as backup method if it's available and allowed
				$settings = self::get_settings();
				$allowed_providers = isset( $settings['allowed_providers'] ) ? $settings['allowed_providers'] : array_keys( Two_Factor_Core::get_providers() );
				
				if ( isset( $providers['Two_Factor_Email'] ) && in_array( 'Two_Factor_Email', $allowed_providers ) ) {
					Two_Factor_Core::enable_provider_for_user( $user->ID, 'Two_Factor_Email' );
					error_log( 'Enabled email 2FA provider for user ' . $user->ID );
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
			wp_redirect( add_query_arg( array(
				'error' => 'session_expired',
				'message' => urlencode( 'Your session has expired. Please log in again.' )
			), wp_login_url() ) );
			exit;
		}
		
		error_log( 'Found stored user for 2FA login: ' . $user->user_login . ' (ID: ' . $user->ID . ')' );
		
		// Ensure backup codes are enabled for users who have TOTP
		self::ensure_backup_codes_enabled_for_user( $user );
		
		// Get provider from URL or use primary
		$provider_class = isset( $_GET['provider'] ) ? sanitize_text_field( $_GET['provider'] ) : null;
		$available_providers = Two_Factor_Core::get_available_providers_for_user( $user );
		$primary_provider = Two_Factor_Core::get_primary_provider_for_user( $user );
		
		error_log( 'Available providers: ' . print_r( array_keys( $available_providers ), true ) );
		error_log( 'Primary provider: ' . ( $primary_provider ? get_class( $primary_provider ) : 'None' ) );
		error_log( 'Requested provider from URL: ' . $provider_class );
		
		if ( $provider_class && isset( $available_providers[ $provider_class ] ) ) {
			$provider = $available_providers[ $provider_class ];
			error_log( 'Using requested provider: ' . get_class( $provider ) );
		} else {
			$provider = $primary_provider;
			error_log( 'Using primary provider: ' . ( $provider ? get_class( $provider ) : 'None' ) );
		}
		
		// **EMAIL PROVIDER SPECIFIC DEBUGGING AND TRIGGER**
		if ( $provider && get_class( $provider ) === 'Two_Factor_Email' ) {
			error_log( 'Email provider selected, attempting to send email' );
			
			// Check if this is the first time loading the email provider
			if ( ! session_id() ) {
				session_start();
			}
			
			// ENSURE USER ID IS STORED PROPERLY - ADD THESE LINES
			if ( !isset( $_SESSION['email_2fa_user_id'] ) && $user ) {
				$_SESSION['email_2fa_user_id'] = $user->ID;
				error_log( 'Stored user ID for email 2FA compatibility: ' . $user->ID );
			}
			
			$email_sent_key = 'email_2fa_sent_' . $user->ID;
			$email_already_sent = isset( $_SESSION[ $email_sent_key ] ) && ( time() - $_SESSION[ $email_sent_key ] ) < 300; // 5 minutes
			
			error_log( 'Email already sent recently: ' . ( $email_already_sent ? 'Yes' : 'No' ) );
			
			if ( ! $email_already_sent ) {
				error_log( 'Calling generate_and_email_token for user: ' . $user->user_email );
				
				// This is the method that should send the email
				$email_result = $provider->generate_and_email_token( $user );
				
				error_log( 'generate_and_email_token result: ' . ( $email_result ? 'SUCCESS' : 'FAILED' ) );
				
				if ( $email_result ) {
					$_SESSION[ $email_sent_key ] = time();
					error_log( 'Marked email as sent at: ' . date( 'Y-m-d H:i:s' ) );
				} else {
					error_log( 'ERROR: Failed to send 2FA email to ' . $user->user_email );
				}
			} else {
				error_log( 'Email was already sent recently, skipping send' );
			}
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
		error_log( 'Backup codes available: ' . ( $backup_available ? 'Yes' : 'No' ) );
		
		// **MAKE THESE VARIABLES AVAILABLE TO THE TEMPLATE**
		// Set variables that the template expects
		$interim_login = false; // Set based on your needs
		$rememberme = ! empty( $_POST['rememberme'] );
		
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
	 * Temporary function to reset user's 2FA for testing
	 * Add this to admin_init hook for testing
	 */
	public static function reset_user_2fa_for_testing() {
		// Only allow this for administrators and only when ?reset_2fa=1 is in URL
		if ( ! current_user_can( 'manage_options' ) || ! isset( $_GET['reset_2fa'] ) ) {
			return;
		}
		
		$user_id = get_current_user_id();
		if ( $user_id ) {
			// Clear all 2FA settings
			delete_user_meta( $user_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY );
			delete_user_meta( $user_id, Two_Factor_Core::PROVIDER_USER_META_KEY );
			delete_user_meta( $user_id, Two_Factor_Totp::SECRET_META_KEY );
			delete_user_meta( $user_id, Two_Factor_Backup_Codes::BACKUP_CODES_META_KEY );
			delete_user_meta( $user_id, Two_Factor_Email::TOKEN_META_KEY );
			delete_user_meta( $user_id, self::USER_2FA_SETUP_FORCED_KEY );
			
			// Mark user as needing 2FA setup
			update_user_meta( $user_id, self::USER_NEEDS_2FA_SETUP_KEY, true );
			
			// Clear sessions
			self::clear_stored_user_for_2fa_setup();
			self::clear_stored_user_for_2fa_login();
			
			wp_redirect( admin_url( '?2fa_reset=success' ) );
			exit;
		}
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
				plugins_url( 'assets/two-factor-frontend.css', __FILE__ ),
				array(),
				'1.0.0'
			);
			
			wp_enqueue_script(
				'two-factor-frontend',
				plugins_url( 'assets/two-factor-frontend.js', __FILE__ ),
				array(),
				'1.0.0',
				true
			);
			
			error_log( 'Enqueued 2FA frontend assets' );
		}
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

	/**
	 * Ensure backup codes and email 2FA are enabled for users who have TOTP
	 *
	 * @param WP_User $user User object
	 */
	private static function ensure_backup_codes_enabled_for_user( $user ) {
		// Check if user has TOTP enabled but not backup codes or email
		$enabled_providers = Two_Factor_Core::get_enabled_providers_for_user( $user );
		$has_totp = array_key_exists( 'Two_Factor_Totp', $enabled_providers );
		$has_backup_codes = array_key_exists( 'Two_Factor_Backup_Codes', $enabled_providers );
		$has_email = array_key_exists( 'Two_Factor_Email', $enabled_providers );
		
		$settings = self::get_settings();
		$allowed_providers = isset( $settings['allowed_providers'] ) ? $settings['allowed_providers'] : array_keys( Two_Factor_Core::get_providers() );
		$providers = Two_Factor_Core::get_providers();
		
		if ( $has_totp && ! $has_backup_codes && isset( $providers['Two_Factor_Backup_Codes'] ) ) {
			error_log( 'User ' . $user->ID . ' has TOTP but no backup codes, enabling backup codes' );
			
			// Enable backup codes provider
			Two_Factor_Core::enable_provider_for_user( $user->ID, 'Two_Factor_Backup_Codes' );
			
			// Generate backup codes if they don't exist
			$backup_provider = $providers['Two_Factor_Backup_Codes'];
			$existing_codes_count = $backup_provider::codes_remaining_for_user( $user );
			
			if ( $existing_codes_count == 0 ) {
				$backup_codes = $backup_provider->generate_codes( $user );
				error_log( 'Generated backup codes for existing user ' . $user->ID . ': ' . count( $backup_codes ) . ' codes' );
				
				// Store backup codes in session for display
				if ( ! session_id() ) {
					session_start();
				}
				$_SESSION['two_factor_backup_codes'] = $backup_codes;
				error_log( 'Stored backup codes in session for existing user display' );
			}
		}
		
		if ( $has_totp && ! $has_email && isset( $providers['Two_Factor_Email'] ) && in_array( 'Two_Factor_Email', $allowed_providers ) ) {
			error_log( 'User ' . $user->ID . ' has TOTP but no email 2FA, enabling email 2FA' );
			Two_Factor_Core::enable_provider_for_user( $user->ID, 'Two_Factor_Email' );
		}
	}

	/**
	 * Add Reset 2FA action to user row actions
	 *
	 * @param array   $actions User row actions
	 * @param WP_User $user    User object
	 * @return array Modified actions
	 */
	public static function add_user_row_actions( $actions, $user ) {
		// Only show for users who can manage users and only if user has 2FA enabled
		if ( ! current_user_can( 'edit_users' ) ) {
			return $actions;
		}
		
		// Don't show for current user (they can use the existing reset function)
		if ( $user->ID === get_current_user_id() ) {
			return $actions;
		}
		
		// Only show if user has 2FA configured
		if ( Two_Factor_Core::is_user_using_two_factor( $user->ID ) ) {
			$reset_url = wp_nonce_url(
				add_query_arg(
					array(
						'action' => 'reset_user_2fa',
						'user_id' => $user->ID,
					),
					admin_url( 'users.php' )
				),
				'reset_2fa_' . $user->ID
			);
			
			$actions['reset_2fa'] = sprintf(
				'<a href="%s" onclick="return confirm(\'%s\')">%s</a>',
				esc_url( $reset_url ),
				esc_js( sprintf( 
					__( 'Are you sure you want to reset two-factor authentication for %s? This will disable all their 2FA methods and require them to set up 2FA again on their next login.', 'two-factor' ),
					$user->display_name 
				) ),
				__( 'Reset 2FA', 'two-factor' )
			);
		}
		
		return $actions;
	}

	/**
	 * Handle admin reset 2FA action
	 */
	public static function handle_admin_reset_2fa() {
		// Check if this is a reset 2FA request
		if ( ! isset( $_GET['action'] ) || $_GET['action'] !== 'reset_user_2fa' ) {
			return;
		}
		
		// Check capabilities
		if ( ! current_user_can( 'edit_users' ) ) {
			wp_die( __( 'You do not have permission to perform this action.', 'two-factor' ) );
		}
		
		// Get and validate user ID
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		if ( ! $user_id ) {
			wp_die( __( 'Invalid user ID.', 'two-factor' ) );
		}
		
		// Verify nonce
		if ( ! wp_verify_nonce( $_GET['_wpnonce'], 'reset_2fa_' . $user_id ) ) {
			wp_die( __( 'Security check failed.', 'two-factor' ) );
		}
		
		// Get user object
		$user = get_user_by( 'ID', $user_id );
		if ( ! $user ) {
			wp_die( __( 'User not found.', 'two-factor' ) );
		}
		
		// Prevent resetting admin's own 2FA through this method
		if ( $user_id === get_current_user_id() ) {
			wp_die( __( 'You cannot reset your own 2FA through this method. Use the existing reset function instead.', 'two-factor' ) );
		}
		
		// Perform the reset
		$reset_result = self::reset_user_2fa( $user_id );
		
		// Log the action
		error_log( sprintf(
		 'Admin %s (%d) reset 2FA for user %s (%d)',
		 wp_get_current_user()->user_login,
		 get_current_user_id(),
		 $user->user_login,
		 $user_id
		) );
		
		// Redirect with success/error message
		$redirect_url = add_query_arg(
			array(
			 'reset_2fa_result' => $reset_result ? 'success' : 'error',
			 'reset_user_name' => urlencode( $user->display_name ),
			),
			admin_url( 'users.php' )
		);
		
		wp_redirect( $redirect_url );
		exit;
	}

	/**
	 * Reset 2FA for a specific user
	 *
	 * @param int $user_id User ID
	 * @return bool Success status
	 */
	public static function reset_user_2fa( $user_id ) {
		// Validate user exists
		$user = get_user_by( 'ID', $user_id );
		if ( ! $user ) {
			return false;
		}
		
		// Prevent affecting current admin session
		$current_user_id = get_current_user_id();
		if ( $user_id === $current_user_id ) {
			error_log( "Attempted to reset 2FA for current user $user_id - blocked" );
			return false;
		}
		
		try {
			// Clear all 2FA settings
			delete_user_meta( $user_id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY );
			delete_user_meta( $user_id, Two_Factor_Core::PROVIDER_USER_META_KEY );
			delete_user_meta( $user_id, Two_Factor_Totp::SECRET_META_KEY );
			delete_user_meta( $user_id, Two_Factor_Backup_Codes::BACKUP_CODES_META_KEY );
			delete_user_meta( $user_id, Two_Factor_Email::TOKEN_META_KEY );
			delete_user_meta( $user_id, self::USER_2FA_SETUP_FORCED_KEY );
			
			// Clear any stored session data for 2FA processes
			delete_user_meta( $user_id, '_two_factor_session_data' );
			
			// Check if 2FA is required for this user
			$settings = self::get_settings();
			$should_require_setup = false;
			
			if ( isset( $settings['force_2fa'] ) && $settings['force_2fa'] ) {
				// Check if user role requires 2FA
				$required_roles = isset( $settings['required_roles'] ) ? $settings['required_roles'] : array();
				
				if ( empty( $required_roles ) ) {
					// Apply to all users
					$should_require_setup = true;
				} else {
					// Check if user has required role
					$user_roles = $user->roles;
					$role_match = array_intersect( $user_roles, $required_roles );
					$should_require_setup = ! empty( $role_match );
				}
			}
			
			// Mark user as needing 2FA setup if required
			if ( $should_require_setup ) {
				update_user_meta( $user_id, self::USER_NEEDS_2FA_SETUP_KEY, true );
				error_log( "Marked user $user_id as needing 2FA setup after reset" );
			} else {
				// Clear the needs setup flag if 2FA is not required
				delete_user_meta( $user_id, self::USER_NEEDS_2FA_SETUP_KEY );
				error_log( "Cleared needs setup flag for user $user_id (2FA not required)" );
			}
			
			// More targeted session destruction - only destroy sessions for the specific user
			// and only if we're not dealing with the current user
			if ( $user_id !== $current_user_id && function_exists( 'wp_destroy_other_sessions' ) ) {
				// This is safer - it only destroys other sessions for the target user
				$sessions = WP_Session_Tokens::get_instance( $user_id );
				if ( $sessions ) {
					$sessions->destroy_all();
					error_log( "Destroyed all sessions for user $user_id" );
				}
			}
			
			error_log( "Successfully reset 2FA for user $user_id ({$user->user_login})" );
			return true;
			
		} catch ( Exception $e ) {
			error_log( "Error resetting 2FA for user $user_id: " . $e->getMessage() );
			return false;
		}
	}

	/**
	 * Display admin notices for 2FA reset actions
	 */
	public static function admin_reset_2fa_notices() {
		// Only show on users.php page
		$screen = get_current_screen();
		if ( ! $screen || $screen->id !== 'users' ) {
			return;
		}
		
		// Check for reset result
		if ( isset( $_GET['reset_2fa_result'] ) ) {
			$result = sanitize_text_field( $_GET['reset_2fa_result'] );
			$user_name = isset( $_GET['reset_user_name'] ) ? sanitize_text_field( $_GET['reset_user_name'] ) : __( 'User', 'two-factor' );
			
			if ( $result === 'success' ) {
				printf(
					'<div class="notice notice-success is-dismissible"><p>%s</p></div>',
					sprintf(
					 __( 'Two-factor authentication has been successfully reset for %s. They will be required to set up 2FA again on their next login.', 'two-factor' ),
					 '<strong>' . esc_html( $user_name ) . '</strong>'
					)
				);
			} elseif ( $result === 'error' ) {
				printf(
					'<div class="notice notice-error is-dismissible"><p>%s</p></div>',
					sprintf(
					 __( 'Failed to reset two-factor authentication for %s. Please try again.', 'two-factor' ),
					 '<strong>' . esc_html( $user_name ) . '</strong>'
					)
				);
			}
		}
	}

	/**
	 * Extend grace period for testing
	 */
	public static function extend_grace_period_for_testing( $time, $user_id, $context ) {
		// For testing: extend grace period to 1 hour
		return 3600;
	}

	/**
	 * Intercept all core 2FA URLs and redirect to our frontend implementation
	 */
	public static function intercept_core_2fa_urls() {
		// Check if this is a wp-login.php 2FA request
		$is_wp_login_2fa = (
			isset($_GET['action']) && 
			in_array($_GET['action'], ['revalidate_2fa', 'validate_2fa']) &&
			(strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false || isset($_GET['loggedout']))
		);
		
		if ($is_wp_login_2fa) {
			error_log('Intercepting core 2FA URL: ' . $_SERVER['REQUEST_URI']);
			
			// Start session to preserve any existing data
			if (!session_id()) {
				session_start();
			}
			
			// Preserve redirect_to parameter
			$redirect_to = isset($_GET['redirect_to']) ? $_GET['redirect_to'] : '';
			if ($redirect_to) {
				$_SESSION['two_factor_redirect_to'] = $redirect_to;
			}
			
			// Try to get user from various sources
			$user = null;
			
			// FOR REVALIDATION: Check current logged-in user first
			if (is_user_logged_in()) {
				$user = wp_get_current_user();
				error_log('Found current logged-in user for revalidation: ' . $user->ID);
			}
			
			// Check session for stored user ID
			if (!$user && isset($_SESSION['email_2fa_user_id'])) {
				$user = get_user_by('id', $_SESSION['email_2fa_user_id']);
				error_log('Found user from session: ' . ($user ? $user->ID : 'null'));
			}
			
			// If we have a user, store in session and redirect to our frontend
			if ($user && $user->ID) {
				$_SESSION['email_2fa_user_id'] = $user->ID;
				$_SESSION['two_factor_login_user_id'] = $user->ID;
				$_SESSION['two_factor_login_timestamp'] = time();
				
				error_log('Redirecting core 2FA to frontend for user: ' . $user->ID);
				wp_redirect(home_url('/account/?action=2fa&two_factor_login=1'));
				exit;
			} else {
				error_log('No user found for core 2FA redirect - redirecting to login');
				wp_redirect(home_url('/account/'));
				exit;
			}
		}
	}
	
	
	
	/**
	 * Override login URLs to point to our frontend
	 */
	public static function override_login_url($login_url, $redirect, $force_reauth) {
		// If this is a 2FA related login URL, redirect to our frontend
		if (strpos($login_url, 'action=revalidate_2fa') !== false || 
			strpos($login_url, 'action=validate_2fa') !== false) {
			
			error_log('Overriding login URL: ' . $login_url);
			
			$frontend_url = home_url('/account/?action=2fa&two_factor_login=1');
			if ($redirect) {
				$frontend_url .= '&redirect_to=' . urlencode($redirect);
			}
			
			return $frontend_url;
		}
		
		return $login_url;
	}

	/**
	 * Comprehensive override for all core 2FA actions and URLs
	 */
	public static function override_core_2fa_action() {
		error_log('Overriding core 2FA action: ' . (isset($_GET['action']) ? $_GET['action'] : 'unknown'));
		
		// Start session
		if (!session_id()) {
			session_start();
		}
		
		// Preserve redirect_to parameter
		if (isset($_GET['redirect_to'])) {
			$_SESSION['two_factor_redirect_to'] = $_GET['redirect_to'];
		}
		
		// Try to get user from current session or WordPress
		$user = wp_get_current_user();
		if (!$user || !$user->ID) {
			// Try to get from our session
			if (isset($_SESSION['email_2fa_user_id'])) {
				$user = get_user_by('id', $_SESSION['email_2fa_user_id']);
			}
		}
		
		if ($user && $user->ID) {
			// Store user in session for our frontend
			$_SESSION['email_2fa_user_id'] = $user->ID;
			$_SESSION['two_factor_login_user_id'] = $user->ID;
			$_SESSION['two_factor_login_timestamp'] = time();
			
			error_log('Redirecting to frontend 2FA for user: ' . $user->ID);
			wp_redirect(home_url('/account/?action=2fa&two_factor_login=1'));
		} else {
			error_log('No user found - redirecting to main account page');
			wp_redirect(home_url('/account/'));
		}
		
		exit;
	}

	/**
	 * Force admin access to 2FA options by manipulating the session
	 */
	public static function force_admin_2fa_access() {		
		// Only for administrators
		if (!current_user_can('manage_options')) {
			return;
		}
		
		// Check if we're in admin area first
		if (!is_admin()) {
			return;
		}
		
		// Add comprehensive debugging
		error_log('=== Admin 2FA Access Check (current_screen hook) ===');
		error_log('Current user can manage options: ' . (current_user_can('manage_options') ? 'YES' : 'NO'));
		error_log('Is admin: ' . (is_admin() ? 'YES' : 'NO'));
		error_log('Request URI: ' . $_SERVER['REQUEST_URI']);
		error_log('Current page: ' . (isset($_GET['page']) ? $_GET['page'] : 'none'));
		
		// Get screen after it's available
		$screen = get_current_screen();
		error_log('Current screen: ' . ($screen ? $screen->id : 'null'));
		error_log('Current screen base: ' . ($screen ? $screen->base : 'null'));
		
		// Enhanced profile page detection
		$is_profile_page = false;
		
		// Method 1: Check screen if available
		if ($screen) {
			$profile_screens = ['profile', 'user-edit'];
			$is_profile_page = in_array($screen->id, $profile_screens) || in_array($screen->base, $profile_screens);
			error_log('Screen-based detection: ' . ($is_profile_page ? 'YES' : 'NO'));
		}
		
		// Method 2: Check URL patterns (more reliable)
		if (!$is_profile_page) {
			$request_uri = $_SERVER['REQUEST_URI'];
			$is_profile_page = (
				strpos($request_uri, '/wp-admin/profile.php') !== false ||
				strpos($request_uri, '/wp-admin/user-edit.php') !== false ||
				(strpos($request_uri, '/wp-admin/') !== false && isset($_GET['user_id']) && is_numeric($_GET['user_id']))
			);
			error_log('URL-based detection: ' . ($is_profile_page ? 'YES' : 'NO'));
		}
		
		// Method 3: Check global variables (most reliable)
		if (!$is_profile_page) {
			global $pagenow;
			$is_profile_page = in_array($pagenow, ['profile.php', 'user-edit.php']);
			error_log('Global $pagenow detection (' . $pagenow . '): ' . ($is_profile_page ? 'YES' : 'NO'));
		}
		
		if (!$is_profile_page) {
			error_log('FAILING - Not a profile page (all methods failed)');
			return;
		}
		
		error_log('SUCCESS - Profile page detected');
		error_log('Checking 2FA session for admin access');
		
		// Check if current user is using 2FA
		$current_user_id = get_current_user_id();
		if (!Two_Factor_Core::is_user_using_two_factor($current_user_id)) {
			error_log('Admin does not have 2FA enabled - no session manipulation needed');
			return;
		}
		
		$session = Two_Factor_Core::get_current_user_session();
		error_log('Current session data: ' . print_r($session, true));
		
		if (!$session || empty($session['two-factor-login'])) {
			error_log('Forcing 2FA session for admin access');
			
			// Set a recent 2FA login timestamp
			$update_result = Two_Factor_Core::update_current_user_session(array(
				'two-factor-login' => time(),
				'two-factor-provider' => 'admin_override'
			));
			
			error_log('Session update result: ' . ($update_result ? 'SUCCESS' : 'FAILED'));
			
			if ($update_result) {
				error_log('Successfully forced 2FA session metadata for admin');
			}
		} else {
			error_log('Admin already has valid 2FA session: ' . $session['two-factor-login']);
		}
	}

	
}
