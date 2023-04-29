const docusign = require('docusign-esign');
const signingViaEmail = require('../eSignature/signingViaEmail');
const fs = require('fs');
const path = require('path');
const prompt = require('prompt-sync')();

const jwtConfig = require('./jwtConfig.json');
const { ProvisioningInformation } = require('docusign-esign');
const demoDocsPath = path.resolve(__dirname, '../documents');
const docFile = 'test.pdf';


const SCOPES = [
     "signature", "impersonation"
];

function getConsent() {
  var urlScopes = SCOPES.join('+');

  // New users will be prompted to go to the following url where there access request needs to be approved by the admin
  var redirectUri = "https://developers.docusign.com/platform/auth/consent";
  var consentUrl = `${jwtConfig.dsOauthServer}/oauth/auth?response_type=code&` +
                      `scope=${urlScopes}&client_id=${jwtConfig.dsJWTClientId}&` +
                      `redirect_uri=${redirectUri}`;

  console.log("Open the following URL in your browser to grant consent to the application:");
  console.log(consentUrl);
  console.log("Consent granted? \n 1)Yes \n 2)No");
  let consentGranted = prompt("");
  if(consentGranted == "1"){
    return true;
  }
   else {
    console.error("Please grant consent!");
    process.exit();
  }
}

// authentication workflow
async function authenticate(){
  // JWT token will be valid for 5 min
  const jwtLifeSec = 5*60, 
  // Api call for creating a new client
    dsApi = new docusign.ApiClient();
  dsApi.setOAuthBasePath(jwtConfig.dsOauthServer.replace('https://', '')); 
  let rsaKey = fs.readFileSync(jwtConfig.privateKeyLocation);

  try {
    // new user will be created
    const results = await dsApi.requestJWTUserToken(jwtConfig.dsJWTClientId,
      jwtConfig.impersonatedUserGuid, SCOPES, rsaKey,
      jwtLifeSec);
    const accessToken = results.body.access_token;

    // getting user info
    const userInfoResults = await dsApi.getUserInfo(accessToken);

    // using the pre existing account if it exists
    let userInfo = userInfoResults.accounts.find(account =>
      account.isDefault === "true");

    return {
      accessToken: results.body.access_token,
      apiAccountId: userInfo.accountId,
      basePath: `${userInfo.baseUri}/restapi`
    };
  } 

  // Catching errors if any arises
  catch(error){
    console.log(error);
    let body = error.response && error.response.body;
    // Determining the source of the error
    if(body){
        // user needs access 
      if (body.error && body.error === 'consent_required') {
        if(getConsent()){ 
          return authenticate();
        };
      } 
      else {
        // access grant has been given 
        // sending api status error
        this._debug_log(`\nAPI problem: Status code ${error.response.status}, message body:
        ${JSON.stringify(body, null, 4)}\n\n`);
      }
    }
  }
}

// If there are no issues with above process users will be allowed to enter the following data fields
function getArgs(apiAccountId, accessToken, basePath){
  signerEmail = prompt("Enter the signer's email address: ");
  signerName = prompt("Enter the signer's name: ");
  senderEmail = prompt("Enter the carbon copy's email address: ");
  senderName = prompt("Enter the carbon copy's name: ");

  // if there are no issues in the process and code doesn't crash then an envelope will be created and it will be sent to the recepient
  const envelopeArgs = {
    signerEmail: signerEmail,
    signerName: signerName,
    senderEmail: senderEmail,
    senderName: senderName,
    status: "sent",
    docFile: path.resolve(demoDocsPath, docFile),
  };

  // sender's basic info is stored here
  const args = {
    accessToken: accessToken,
    basePath: basePath,
    accountId: apiAccountId,
    envelopeArgs: envelopeArgs
  };

  return args
}


async function main(){
  // Workflow of the process

  // to check if users are authenticated
  let accountInfo = await authenticate();
  // if they are authenticated then get their credentials
  let args = getArgs(accountInfo.apiAccountId, accountInfo.accessToken, accountInfo.basePath);
  // if no errors arise proceed to create an envelope and send it
  let envelopeId = signingViaEmail.sendEnvelope(args);
  // Process is complete and envelopeId  is sent to the sender
  console.log(envelopeId);
}

main();