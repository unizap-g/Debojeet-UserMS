import sgMail from '@sendgrid/mail';

// Set the API key from the environment variables as soon as the service is loaded
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/**
 * Sends a transactional email with a dynamic template for the OTP.
 * @param {string} email - The recipient's email address.
 * @param {string} otp - The 6-digit One-Time Password.
 * @returns {Promise<boolean>} - True if the email was sent successfully, false otherwise.
 */
export const sendOtpEmail = async (email, otp) => {
  
  // This is the message object that SendGrid expects
  const msg = {
    to: email,
    from: process.env.SENDGRID_FROM_EMAIL, // This MUST be a verified sender in your SendGrid account
    templateId: process.env.SENDGRID_TEMPLATE_ID,
    
    // This object contains the dynamic data that will be inserted into your template.
    // The key ('otp' in this case) must match the substitution tag in your SendGrid template.
    // e.g., {{otp}}
    dynamic_template_data: {
      otp: otp,
    },
  };

  try {
    // Send the email
    await sgMail.send(msg);
    console.log(`[LOG] OTP email dispatched successfully to ${email} via SendGrid.`);
    return true;

  } catch (error) {
    // Log detailed errors for easier debugging
    console.error('❌ CRITICAL: Failed to send SendGrid email:');
    if (error.response) {
      // SendGrid provides detailed error messages in the response body
      console.error(error.response.body);
    } else {
      console.error(error);
    }
    return false;
  }
};

