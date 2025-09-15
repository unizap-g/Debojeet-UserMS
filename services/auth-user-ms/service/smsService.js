import axios from 'axios';

/**
 * Sends an OTP via SMS, with a built-in simulation mode for development.
 * @param {string} fullMobileNumber - The recipient's full mobile number, including country code.
 * @param {string} otp - The 6-digit One-Time Password.
 * @returns {Promise<boolean>} - True if the SMS was sent/simulated successfully, false otherwise.
 */
export const sendOtpSms = async (fullMobileNumber, otp) => {

  // --- Development & QA Safe Mode (DISABLED) ---
  // The simulation block has been commented out to allow sending real SMS messages.
  /*
  if (process.env.NODE_ENV !== 'production') {
     console.log('----------------------------------------------------');
     console.log(`[DEVELOPMENT SMS SIMULATION]`);
     console.log(`  Recipient: ${fullMobileNumber}`);
     console.log(`  OTP Code: ${otp}`);
     console.log('----------------------------------------------------');
     return true; // Simulate a successful send
  }
  */

  // --- Production Logic (NOW ALWAYS ACTIVE) ---
  // This code will now run every time the function is called.
  try {
    const apiUrl = process.env.SMS_API_URL;
    const authKey = process.env.SMS_AUTH_KEY;
    const templateId = process.env.SMS_TEMPLATE_ID;
    
    // These are specific to your MSG91 setup and may not be required by all providers
    const appHash = process.env.SMS_HELLO_APP_HASH;
    const phpSessId = process.env.SMS_PHPSESSID || '';

    const payload = {
      template_id: templateId,
      recipients: [
        {
          mobiles: fullMobileNumber,
          "number": otp // The key for the OTP value might be different for other APIs
        }
      ]
    };

    const headers = {
      'Accept': 'application/json',
      'authkey': authKey,
      'Content-Type': 'application/json',
      'Cookie': `HELLO_APP_HASH=${appHash}; PHPSESSID=${phpSessId}`
    };

    console.log(`Sending real SMS to ${fullMobileNumber}...`);
    const response = await axios.post(apiUrl, payload, { headers });
    
    console.log('Real SMS sent successfully. Response:', response.data);
    return true;

  } catch (error) {
    console.error('❌ CRITICAL: Failed to send real SMS:');
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    } else {
      console.error('Error Message:', error.message);
    }
    return false;
  }
};

