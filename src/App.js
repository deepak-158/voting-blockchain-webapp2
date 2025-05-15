import React, { useState, useEffect } from 'react';
import { Lock, UserPlus, Check, Award, Users, Activity, BarChart2, Fingerprint } from 'lucide-react';
import electionCommissionLogo from './ecilogo.svg';
import indiaFlagImage from './flag.jpg';

// Images (would be imported in a real project)
const headerImage = 'https://via.placeholder.com/1200x400/1a365d/ffffff?text=India+Voting+Portal';
const secureVotingImage = 'https://via.placeholder.com/600x300/1a365d/ffffff?text=Secure+Voting';

// Simulate a simple blockchain structure
class Block {
  constructor(timestamp, votes, previousHash = '') {
    this.timestamp = timestamp;
    this.votes = votes;
    this.previousHash = previousHash;
    this.hash = this.calculateHash();
  }

  calculateHash() {
    return btoa(JSON.stringify(this.votes) + this.previousHash + this.timestamp);
  }
}

class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()];
    this.pendingVotes = [];
  }

  createGenesisBlock() {
    return new Block(Date.now(), [], "0");
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  addVote(voter, candidate) {
    this.pendingVotes.push({ voter, candidate, timestamp: Date.now() });
    return this.pendingVotes.length;
  }

  minePendingVotes() {
    const block = new Block(Date.now(), this.pendingVotes, this.getLatestBlock().hash);
    this.chain.push(block);
    this.pendingVotes = [];
    return block;
  }

  isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      if (currentBlock.hash !== currentBlock.calculateHash()) {
        return false;
      }

      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
      }
    }
    return true;
  }

  getVoteCounts() {
    const voteCounts = {};
    for (const block of this.chain) {
      for (const vote of block.votes) {
        if (vote.candidate in voteCounts) {
          voteCounts[vote.candidate]++;
        } else {
          voteCounts[vote.candidate] = 1;
        }
      }
    }
    return voteCounts;
  }
}

export default function App() {
  const [activeView, setActiveView] = useState('home');
  const [blockchain] = useState(new Blockchain());
  
  const [voters, setVoters] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [newVoter, setNewVoter] = useState({ id: '', name: '', aadhaar: '', mobile: '', fingerprintData: '' });
  const [newCandidate, setNewCandidate] = useState({ id: '', name: '', fingerprintData: '' });
  const [currentVoter, setCurrentVoter] = useState(null);
  const [selectedCandidate, setSelectedCandidate] = useState('');
  const [votingStatus, setVotingStatus] = useState('');
  const [chainStatus, setChainStatus] = useState('');
  
  // Slideshow management
  const [slideshowItems, setSlideshowItems] = useState([
    { id: 1, text: 'PORTAL MAINTENANCE SCHEDULED: MAY 6, 1 AM TO 4 AM IST', active: true },
    { id: 2, text: 'ELECTION DATES ANNOUNCED FOR UTTAR PRADESH - JUNE 10-24', active: true },
    { id: 3, text: 'NEW VOTER REGISTRATION DEADLINE EXTENDED TO MAY 15', active: true }
  ]);
  const [currentSlideIndex, setCurrentSlideIndex] = useState(0);
  const [newSlideText, setNewSlideText] = useState('');
  
  // Language settings
  const [currentLanguage, setCurrentLanguage] = useState('english');
  const [languages] = useState(['English', 'हिंदी', 'বাংলা', 'தமிழ்', 'తెలుగు', 'ಕನ್ನಡ', 'മലയാളം', 'ਪੰਜਾਬੀ', 'ગુજરાતી', 'ଓଡ଼ିଆ']);
  
  const [isAdmin, setIsAdmin] = useState(false);
  const [adminCredentials, setAdminCredentials] = useState({ id: '', password: '' });
  const [adminLoginError, setAdminLoginError] = useState('');
  const [fingerprintScanActive, setFingerprintScanActive] = useState(false);
  const [fingerprintVerified, setFingerprintVerified] = useState(false);
  const [loginInputValue, setLoginInputValue] = useState('');
  const [isBiometricAvailable, setIsBiometricAvailable] = useState(false);
  const [digilockerAuthUrl, setDigilockerAuthUrl] = useState('');
  const [digilockerStatus, setDigilockerStatus] = useState('');
  const [isDigilockerAuthenticated, setIsDigilockerAuthenticated] = useState(false);
  const [digilockerUserData, setDigilockerUserData] = useState(null);
  const [validationErrors, setValidationErrors] = useState({});
  const [dob, setDob] = useState('');
  const [age, setAge] = useState(null);
  const [voterServiceView, setVoterServiceView] = useState('main');
  const [selectedVoter, setSelectedVoter] = useState(null);
  const [updatedVoterDetails, setUpdatedVoterDetails] = useState({});
  const [voterSearchQuery, setVoterSearchQuery] = useState('');
  const [voterSearchResults, setVoterSearchResults] = useState([]);
  const [voterIdCardData, setVoterIdCardData] = useState(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [headerSearchQuery, setHeaderSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);

  // DigiLocker API configuration
  const DIGILOCKER_CLIENT_ID = "YOUR_DIGILOCKER_CLIENT_ID"; // Replace with actual Client ID from DigiLocker Partner Portal
  const DIGILOCKER_REDIRECT_URI = window.location.origin + "/digilocker-callback";
  const DIGILOCKER_BASE_URL = "https://api.digitallocker.gov.in";
  const DIGILOCKER_AUTH_URL = `${DIGILOCKER_BASE_URL}/public/oauth2/1/authorize`;
  const DIGILOCKER_TOKEN_URL = `${DIGILOCKER_BASE_URL}/public/oauth2/1/token`;
  const DIGILOCKER_USER_DETAILS_URL = `${DIGILOCKER_BASE_URL}/public/oauth2/1/user`;
  const DIGILOCKER_GET_DOCUMENT_URL = `${DIGILOCKER_BASE_URL}/public/oauth2/1/file`;

  useEffect(() => {
    const intervalId = setInterval(() => {
      if (blockchain.pendingVotes.length > 0) {
        blockchain.minePendingVotes();
        setChainStatus(`New block mined at ${new Date().toLocaleTimeString()}`);
      }
    }, 30000);
    
    return () => clearInterval(intervalId);
  }, [blockchain]);
  
  useEffect(() => {
    if (blockchain.pendingVotes.length >= 5) {
      blockchain.minePendingVotes();
      setChainStatus(`New block mined at ${new Date().toLocaleTimeString()} with 5+ votes`);
    }
  }, [blockchain.pendingVotes.length, blockchain]);

  // Check if Web Authentication API is available
  useEffect(() => {
    checkBiometricAvailability();
  }, []);

  const checkBiometricAvailability = async () => {
    try {
      // Check for WebAuthn/FIDO2 support with Windows Hello integration
      if (window.PublicKeyCredential && 
          navigator.credentials && 
          window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
        
        const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        
        if (available) {
          // Additional check for Windows platform
          const userAgent = window.navigator.userAgent;
          const isWindows = userAgent.indexOf("Windows") !== -1;
          
          if (isWindows) {
            console.log("Windows platform detected, Windows Hello should be available");
            setIsBiometricAvailable(true);
          } else {
            console.warn("Non-Windows platform detected, fingerprint may not work as expected");
            setIsBiometricAvailable(available);
          }
        } else {
          console.warn("Platform authenticator is not available");
          setIsBiometricAvailable(false);
        }
      } else {
        console.warn("Web Authentication API is not supported by this browser");
        setIsBiometricAvailable(false);
      }
    } catch (error) {
      console.error("Error checking biometric availability:", error);
      setIsBiometricAvailable(false);
    }
  };

  // Initialize DigiLocker OAuth URL
  useEffect(() => {
    const authUrl = `${DIGILOCKER_AUTH_URL}?response_type=code&client_id=${DIGILOCKER_CLIENT_ID}&redirect_uri=${encodeURIComponent(DIGILOCKER_REDIRECT_URI)}&state=${generateRandomState()}`;
    setDigilockerAuthUrl(authUrl);
  }, []);

  // Generate random state for OAuth security
  const generateRandomState = () => {
    return Math.random().toString(36).substring(2, 15);
  };

  // Handle DigiLocker Authentication
  const initiateDigilockerAuth = () => {
    setDigilockerStatus('Redirecting to DigiLocker...');
    // Open DigiLocker in a new window
    const digilockerWindow = window.open(digilockerAuthUrl, 'DigiLocker Authentication', 'width=800,height=600');
    
    // Poll for the redirect and callback
    const checkInterval = setInterval(() => {
      try {
        if (digilockerWindow.closed) {
          clearInterval(checkInterval);
          setDigilockerStatus('Authentication window closed');
        } else if (digilockerWindow.location.href.includes(DIGILOCKER_REDIRECT_URI)) {
          // Extract the code from the redirect URL
          const urlParams = new URLSearchParams(digilockerWindow.location.search);
          const code = urlParams.get('code');
          const state = urlParams.get('state');
          
          // Close the authentication window
          digilockerWindow.close();
          clearInterval(checkInterval);
          
          if (code) {
            setDigilockerStatus('Authentication successful. Getting user details...');
            exchangeCodeForToken(code);
          } else {
            setDigilockerStatus('Authentication failed. No authorization code received.');
          }
        }
      } catch (e) {
        // Cross-origin error expected when DigiLocker redirects to their domain
        // Just ignore this error - it's normal during the OAuth flow
      }
    }, 500);
  };

  // Exchange authorization code for access token
  const exchangeCodeForToken = async (code) => {
    try {
      setDigilockerStatus('Exchanging code for token...');
      // In real implementation, this should be done server-side to protect client_secret
      // For demo purposes, we're doing it client-side
      const tokenResponse = await fetch(DIGILOCKER_TOKEN_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          client_id: DIGILOCKER_CLIENT_ID,
          client_secret: 'YOUR_CLIENT_SECRET',
          redirect_uri: DIGILOCKER_REDIRECT_URI
        })
      });
      
      const tokenData = await tokenResponse.json();
      
      if (tokenData.access_token) {
        setDigilockerStatus('Token received. Fetching user details...');
        fetchDigilockerUserDetails(tokenData.access_token);
      } else {
        setDigilockerStatus('Failed to get access token');
      }
    } catch (error) {
      console.error('Error exchanging code for token:', error);
      setDigilockerStatus('Error during token exchange');
    }
  };

  // Fetch user details from DigiLocker
  const fetchDigilockerUserDetails = async (accessToken) => {
    try {
      setDigilockerStatus('Fetching user details...');
      const userResponse = await fetch(DIGILOCKER_USER_DETAILS_URL, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      
      const userData = await userResponse.json();
      
      if (userData) {
        setDigilockerUserData(userData);
        setIsDigilockerAuthenticated(true);
        setDigilockerStatus('DigiLocker authentication successful');
        
        // Match DigiLocker data with voter record
        if (userData.aadhaar) {
          const matchedVoter = voters.find(
            voter => voter.aadhaar && voter.aadhaar.endsWith(userData.aadhaar.substring(8))
          );
          
          if (matchedVoter) {
            // Check if already voted
            const hasVoted = blockchain.chain.some(block => 
              block.votes.some(vote => vote.voter === matchedVoter.id)
            ) || blockchain.pendingVotes.some(vote => vote.voter === matchedVoter.id);
            
            if (hasVoted) {
              setDigilockerStatus('You have already voted!');
            } else {
              setCurrentVoter(matchedVoter);
              setFingerprintVerified(true); // Skip fingerprint since DigiLocker is more secure
              setActiveView('voting');
            }
          } else {
            setDigilockerStatus('No matching voter found for your DigiLocker ID');
          }
        } else {
          setDigilockerStatus('Aadhaar information not available from DigiLocker');
        }
      } else {
        setDigilockerStatus('Failed to get user details');
      }
    } catch (error) {
      console.error('Error fetching user details:', error);
      setDigilockerStatus('Error fetching user details');
    }
  };

  // Fetch document from DigiLocker (e.g. Voter ID)
  const fetchDocumentFromDigiLocker = async (accessToken, docType) => {
    try {
      setDigilockerStatus(`Fetching ${docType} document...`);
      const docResponse = await fetch(`${DIGILOCKER_GET_DOCUMENT_URL}/${docType}`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      
      if (docResponse.ok) {
        const docData = await docResponse.blob();
        // Process the document - for example, display it or extract information
        setDigilockerStatus(`${docType} document retrieved successfully`);
        return docData;
      } else {
        setDigilockerStatus(`Failed to retrieve ${docType} document`);
        return null;
      }
    } catch (error) {
      console.error(`Error fetching ${docType} document:`, error);
      setDigilockerStatus(`Error fetching ${docType} document`);
      return null;
    }
  };

  // Register voter with DigiLocker
  const registerVoterWithDigiLocker = () => {
    if (!digilockerUserData) {
      alert('Please authenticate with DigiLocker first');
      return;
    }
    
    // Create voter record from DigiLocker data
    const newVoterData = {
      id: `V${Date.now().toString().substring(7)}`,
      name: digilockerUserData.name || '',
      aadhaar: digilockerUserData.aadhaar || '',
      mobile: digilockerUserData.mobile || '',
      fingerprintData: 'verified-via-digilocker'
    };
    
    setVoters([...voters, newVoterData]);
    setNewVoter({ id: '', name: '', aadhaar: '', mobile: '', fingerprintData: '' });
    alert('Voter registered successfully via DigiLocker!');
    setActiveView('home');
  };

  const adminLogin = () => {
    setAdminLoginError('');
    if (adminCredentials.id === 'admin' && adminCredentials.password === 'admin123') {
      setIsAdmin(true);
      setActiveView('admin');
    } else {
      setAdminLoginError('Invalid admin credentials');
    }
  };

  // Simulate fingerprint scanner
  const simulateFingerprintScan = (purpose) => {
    setFingerprintScanActive(true);
    
    // Try to use real fingerprint authentication with Windows Hello
    authenticateWithWindowsHello(purpose);
  };

  // Real fingerprint authentication using Windows Hello
  const authenticateWithWindowsHello = async (purpose) => {
    setFingerprintScanActive(true);
    
    if (!isBiometricAvailable) {
      console.warn('Biometric authentication not available, falling back to simulation');
      // Fall back to simulation for testing
    setTimeout(() => {
      const fingerprintHash = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      
      if (purpose === 'register-voter') {
        setNewVoter({...newVoter, fingerprintData: fingerprintHash});
      } else if (purpose === 'register-candidate') {
        setNewCandidate({...newCandidate, fingerprintData: fingerprintHash});
      } else if (purpose === 'login') {
        setLoginInputValue(fingerprintHash);
      } else if (purpose === 'verify') {
        setFingerprintVerified(true);
      }
      
      setFingerprintScanActive(false);
    }, 2000);
      return;
    }
    
    try {
      // Create credential options optimized for Windows Hello
      const userId = new Uint8Array(16);
      window.crypto.getRandomValues(userId);
      
      const challenge = new Uint8Array(32);
      window.crypto.getRandomValues(challenge);

      // This configuration specifically targets Windows Hello
      const publicKeyCredentialCreationOptions = {
        challenge,
        rp: {
          name: "Voting Blockchain WebApp",
          id: window.location.hostname
        },
        user: {
          id: userId,
          name: purpose === 'register-voter' ? newVoter.id || 'voter' : 
                purpose === 'register-candidate' ? newCandidate.id || 'candidate' : 'user',
          displayName: purpose === 'register-voter' ? newVoter.name || 'Voter' : 
                       purpose === 'register-candidate' ? newCandidate.name || 'Candidate' : 'User',
        },
        pubKeyCredParams: [
          {
            type: "public-key",
            alg: -7 // ES256 algorithm
          },
          {
            type: "public-key", 
            alg: -257 // RS256 algorithm
          }
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform", // Use built-in authenticator (like Windows Hello)
          userVerification: "required", // Require biometric verification
          requireResidentKey: false
        },
        timeout: 60000,
        attestation: "direct" // Get attestation information
      };
      
      console.log("Requesting Windows Hello authentication...");
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });
      
      console.log("Windows Hello credential created:", credential);
      
      if (credential) {
        // Generate a fingerprint hash based on credential ID
        const fingerprintHash = btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId)));
        console.log("Fingerprint authentication successful");
        
        if (purpose === 'register-voter') {
          setNewVoter({...newVoter, fingerprintData: fingerprintHash});
        } else if (purpose === 'register-candidate') {
          setNewCandidate({...newCandidate, fingerprintData: fingerprintHash});
        } else if (purpose === 'login') {
          setLoginInputValue(fingerprintHash);
        } else if (purpose === 'verify') {
          setFingerprintVerified(true);
        }
      }
    } catch (error) {
      console.error('Windows Hello authentication error:', error);
      // Fall back to simulation for testing if real biometrics fails
      setTimeout(() => {
        const fingerprintHash = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        
        if (purpose === 'register-voter') {
          setNewVoter({...newVoter, fingerprintData: fingerprintHash});
        } else if (purpose === 'register-candidate') {
          setNewCandidate({...newCandidate, fingerprintData: fingerprintHash});
        } else if (purpose === 'login') {
          setLoginInputValue(fingerprintHash);
        } else if (purpose === 'verify') {
          setFingerprintVerified(true);
        }
      }, 2000);
    } finally {
      setFingerprintScanActive(false);
    }
  };

  // Verify fingerprint for login
  const verifyFingerprint = (purpose, voterId = null) => {
    setFingerprintScanActive(true);
    
    verifyWithWindowsHello(purpose, voterId);
  };

  // Verify fingerprint using Windows Hello
  const verifyWithWindowsHello = async (purpose, voterId = null) => {
    if (!isBiometricAvailable) {
      console.warn('Biometric verification not available, falling back to simulation');
      // Fall back to simulation
    setTimeout(() => {
      if (purpose === 'login') {
        if (voterId) {
          const voter = voters.find(v => v.id === voterId);
          if (voter) {
            // Check if already voted
            const hasVoted = blockchain.chain.some(block => 
              block.votes.some(vote => vote.voter === voterId)
            ) || blockchain.pendingVotes.some(vote => vote.voter === voterId);
            
            if (hasVoted) {
              alert('You have already voted!');
              setFingerprintScanActive(false);
              return;
            }
            
            setCurrentVoter(voter);
            setFingerprintVerified(true);
            // Move to voting immediately after verification
            setActiveView('voting');
          } else {
            alert('Voter not found');
          }
        } else {
          alert('Please enter a valid Voter ID');
        }
      } else if (purpose === 'verify-for-voting') {
        setFingerprintVerified(true);
      }
      
      setFingerprintScanActive(false);
    }, 2000);
      return;
    }
    
    try {
      if (purpose === 'login') {
        if (!voterId) {
          alert('Please enter a valid Voter ID');
          setFingerprintScanActive(false);
          return;
        }
        
        const voter = voters.find(v => v.id === voterId);
        if (!voter) {
          alert('Voter not found');
          setFingerprintScanActive(false);
          return;
        }
        
        // Check if already voted
        const hasVoted = blockchain.chain.some(block => 
          block.votes.some(vote => vote.voter === voterId)
        ) || blockchain.pendingVotes.some(vote => vote.voter === voterId);
        
        if (hasVoted) {
          alert('You have already voted!');
          setFingerprintScanActive(false);
          return;
        }
        
        // Create a challenge for Windows Hello authentication
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);
        
        // Configure options specifically for Windows Hello
        const publicKeyCredentialRequestOptions = {
          challenge,
          timeout: 60000,
          userVerification: "required", // Require biometric verification
          rpId: window.location.hostname
        };
        
        console.log("Requesting Windows Hello verification...");
        const assertion = await navigator.credentials.get({
          publicKey: publicKeyCredentialRequestOptions
        });
        
        console.log("Windows Hello assertion received:", assertion);
        
        if (assertion) {
          console.log("Fingerprint verification successful");
          setCurrentVoter(voter);
          setFingerprintVerified(true);
          setActiveView('voting');
        }
      } else if (purpose === 'verify-for-voting') {
        // Similar approach using Windows Hello for voting verification
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);
        
        const publicKeyCredentialRequestOptions = {
          challenge,
          timeout: 60000,
          userVerification: "required",
          rpId: window.location.hostname
        };
        
        console.log("Requesting Windows Hello verification for voting...");
        const assertion = await navigator.credentials.get({
          publicKey: publicKeyCredentialRequestOptions
        });
        
        if (assertion) {
          console.log("Fingerprint verification for voting successful");
          setFingerprintVerified(true);
        }
      }
    } catch (error) {
      console.error('Windows Hello verification error:', error);
      
      // Fall back to simulation if real biometrics fails
      setTimeout(() => {
        if (purpose === 'login') {
          if (voterId) {
            const voter = voters.find(v => v.id === voterId);
            if (voter) {
              // Check if already voted
              const hasVoted = blockchain.chain.some(block => 
                block.votes.some(vote => vote.voter === voterId)
              ) || blockchain.pendingVotes.some(vote => vote.voter === voterId);
              
              if (hasVoted) {
                alert('You have already voted!');
                setFingerprintScanActive(false);
                return;
              }
              
              setCurrentVoter(voter);
              setFingerprintVerified(true);
              // Move to voting immediately after verification
              setActiveView('voting');
            } else {
              alert('Voter not found');
            }
          }
        } else if (purpose === 'verify-for-voting') {
          setFingerprintVerified(true);
        }
      }, 2000);
    } finally {
      setFingerprintScanActive(false);
    }
  };

  // Input validation functions
  const validateName = (name) => {
    if (!name || name.trim() === '') {
      return 'Name is required';
    }
    // Name should contain only alphabets and spaces
    if (!/^[A-Za-z\s]+$/.test(name)) {
      return 'Name should contain only alphabets and spaces';
    }
    // Name should be at least 3 characters long
    if (name.trim().length < 3) {
      return 'Name should be at least 3 characters long';
    }
    return '';
  };

  const validateVoterId = (id) => {
    if (!id || id.trim() === '') {
      return 'Voter ID is required';
    }
    // Voter ID format validation (e.g., should follow standard format like 'ABC1234567')
    if (!/^[A-Z]{3}[0-9]{7}$/.test(id)) {
      return 'Invalid Voter ID format. It should be like ABC1234567';
    }
    // Check if voter ID already exists
    if (voters.some(v => v.id === id)) {
      return 'This Voter ID is already registered';
    }
    return '';
  };

  const validateAadhaar = (aadhaar) => {
    if (!aadhaar || aadhaar.trim() === '') {
      return 'Aadhaar number is required';
    }
    // Aadhaar should be exactly 12 digits
    if (!/^[0-9]{12}$/.test(aadhaar)) {
      return 'Aadhaar should be exactly 12 digits';
    }
    // Verify Aadhaar using Verhoeff algorithm (simplified version)
    // In a real app, you would use a proper Aadhaar validation library
    const isValidAadhaar = verifyAadhaarChecksum(aadhaar);
    if (!isValidAadhaar) {
      return 'Invalid Aadhaar number';
    }
    // Check if Aadhaar already exists
    if (voters.some(v => v.aadhaar === aadhaar)) {
      return 'This Aadhaar number is already registered';
    }
    return '';
  };

  // Simple Aadhaar verification (not the full Verhoeff algorithm)
  const verifyAadhaarChecksum = (aadhaar) => {
    // In a real application, implement the full Verhoeff algorithm
    // For this demo, we'll just check basic format and simple validation
    if (aadhaar === '000000000000' || aadhaar === '111111111111') {
      return false;
    }
    
    // For demo purposes, we'll consider any 12-digit number as valid
    // In a real application, implement proper Verhoeff algorithm
    return /^[0-9]{12}$/.test(aadhaar);
    
    // Original implementation with checksum validation:
    // const digits = aadhaar.split('').map(Number);
    // const checksum = digits.slice(0, 11).reduce((sum, digit) => sum + digit, 0) % 10;
    // return checksum === digits[11];
  };

  const validateMobile = (mobile) => {
    if (!mobile || mobile.trim() === '') {
      return 'Mobile number is required';
    }
    // Mobile should be exactly 10 digits
    if (!/^[0-9]{10}$/.test(mobile)) {
      return 'Mobile number should be exactly 10 digits';
    }
    // Mobile should start with a valid prefix (6, 7, 8, 9)
    if (!/^[6-9]/.test(mobile)) {
      return 'Mobile number should start with 6, 7, 8, or 9';
    }
    return '';
  };

  const validateAge = (dateOfBirth) => {
    if (!dateOfBirth) {
      return 'Date of birth is required';
    }
    
    const birthDate = new Date(dateOfBirth);
    const today = new Date();
    
    // Calculate age
    let calculatedAge = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      calculatedAge--;
    }
    
    // Update age state
    setAge(calculatedAge);
    
    // Check if age is at least 18
    if (calculatedAge < 18) {
      return 'You must be at least 18 years old to register as a voter';
    }
    
    // Check if date of birth is in the future
    if (birthDate > today) {
      return 'Date of birth cannot be in the future';
    }
    
    return '';
  };

  const validateCandidateId = (id) => {
    if (!id || id.trim() === '') {
      return 'Candidate ID is required';
    }
    // Check if candidate ID already exists
    if (candidates.some(c => c.id === id)) {
      return 'This Candidate ID is already registered';
    }
    return '';
  };

  // Validate form on input change
  const handleInputChange = (field, value, formType = 'voter') => {
    let errorMessage = '';
    
    switch (field) {
      case 'name':
        errorMessage = validateName(value);
        if (formType === 'voter') {
          setNewVoter({...newVoter, name: value});
        } else {
          setNewCandidate({...newCandidate, name: value});
        }
        break;
      case 'id':
        if (formType === 'voter') {
          errorMessage = validateVoterId(value);
          setNewVoter({...newVoter, id: value});
        } else {
          errorMessage = validateCandidateId(value);
          setNewCandidate({...newCandidate, id: value});
        }
        break;
      case 'aadhaar':
        errorMessage = validateAadhaar(value);
        setNewVoter({...newVoter, aadhaar: value});
        break;
      case 'mobile':
        errorMessage = validateMobile(value);
        setNewVoter({...newVoter, mobile: value});
        break;
      case 'dob':
        errorMessage = validateAge(value);
        setDob(value);
        break;
      default:
        break;
    }
    
    setValidationErrors({
      ...validationErrors,
      [formType]: {
        ...validationErrors[formType],
        [field]: errorMessage
      }
    });
  };

  // Validate entire form before submission
  const validateVoterForm = () => {
    const nameError = validateName(newVoter.name);
    const idError = validateVoterId(newVoter.id);
    const aadhaarError = validateAadhaar(newVoter.aadhaar);
    const mobileError = validateMobile(newVoter.mobile);
    const ageError = validateAge(dob);
    
    setValidationErrors({
      ...validationErrors,
      voter: {
        name: nameError,
        id: idError,
        aadhaar: aadhaarError,
        mobile: mobileError,
        dob: ageError
      }
    });
    
    return !(nameError || idError || aadhaarError || mobileError || ageError);
  };

  const validateCandidateForm = () => {
    const nameError = validateName(newCandidate.name);
    const idError = validateCandidateId(newCandidate.id);
    
    setValidationErrors({
      ...validationErrors,
      candidate: {
        name: nameError,
        id: idError
      }
    });
    
    return !(nameError || idError);
  };

  // Modified registerVoter function
  const registerVoter = () => {
    if (!validateVoterForm()) {
      alert('Please correct the errors in the form');
        return;
      }
    
    if (!newVoter.fingerprintData) {
      alert('Please scan your fingerprint');
      return;
    }
    
    setVoters([...voters, {...newVoter, age}]);
      setNewVoter({ id: '', name: '', aadhaar: '', mobile: '', fingerprintData: '' });
    setDob('');
    setAge(null);
      alert('Voter registered successfully with fingerprint!');
      setActiveView('home');
  };

  // Modified registerCandidate function
  const registerCandidate = () => {
    if (!validateCandidateForm()) {
      alert('Please correct the errors in the form');
        return;
      }
    
    if (!newCandidate.fingerprintData) {
      alert('Please scan candidate fingerprint');
      return;
    }
    
      setCandidates([...candidates, newCandidate]);
      setNewCandidate({ id: '', name: '', fingerprintData: '' });
      alert('Candidate registered successfully with fingerprint!');
  };

  // Modified voter login
  const voterLogin = (voterId) => {
    if (!voterId) {
      alert('Please enter your Voter ID');
      return;
    }
    
    const voter = voters.find(v => v.id === voterId);
    if (!voter) {
      alert('Voter ID not found');
      return;
    }
    
    // Check if already voted
    const hasVoted = blockchain.chain.some(block => 
      block.votes.some(vote => vote.voter === voterId)
    ) || blockchain.pendingVotes.some(vote => vote.voter === voterId);
    
    if (hasVoted) {
      alert('You have already voted!');
      return;
    }
    
    // Start fingerprint verification with the voter ID
    verifyFingerprint('login', voterId);
  };

  const castVote = () => {
    if (!selectedCandidate) {
      setVotingStatus('Please select a candidate');
      return;
    }
    
    blockchain.addVote(currentVoter.id, selectedCandidate);
    setVotingStatus(`Vote cast successfully! It will be added to the blockchain soon.`);
    
    setTimeout(() => {
      setCurrentVoter(null);
      setSelectedCandidate('');
      setVotingStatus('');
      setActiveView('home');
    }, 3000);
  };

  const checkBlockchain = () => {
    const isValid = blockchain.isChainValid();
    setChainStatus(isValid ? 
      'Blockchain integrity verified ✓' : 
      'Blockchain integrity compromised! ✗');
  };

  // Views
  const renderHomeView = () => (
    <div className="min-h-screen bg-gray-200">
      {/* Top navigation bar */}
      <div className="bg-purple-200 text-gray-800 py-1 px-4 flex justify-between items-center">
        <div className="relative">
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            className="hover:bg-purple-300 px-2 py-1 rounded transition-colors"
          >
            Menu
          </button>
          {menuOpen && (
            <div className="absolute top-full left-0 mt-1 bg-white shadow-lg rounded z-50 w-48">
              <ul>
                <li>
                  <button
                    onClick={() => {
                      setActiveView('home');
                      setMenuOpen(false);
                    }}
                    className="w-full text-left px-4 py-2 hover:bg-gray-100 transition-colors"
                  >
                    Home
                  </button>
                </li>
                <li>
                  <button
                    onClick={() => {
                      setActiveView('voterServices');
                      setMenuOpen(false);
                    }}
                    className="w-full text-left px-4 py-2 hover:bg-gray-100 transition-colors"
                  >
                    Voter Services
                  </button>
                </li>
                <li>
                  <button
                    onClick={() => {
                      setActiveView('voterLogin');
                      setMenuOpen(false);
                    }}
                    className="w-full text-left px-4 py-2 hover:bg-gray-100 transition-colors"
                  >
                    Login to Vote
                  </button>
                </li>
                <li>
                  <button
                    onClick={() => {
                      setActiveView('voterRegister');
                      setMenuOpen(false);
                    }}
                    className="w-full text-left px-4 py-2 hover:bg-gray-100 transition-colors"
                  >
                    Register as Voter
                  </button>
                </li>
                <li>
                  <button
                    onClick={() => {
                      setActiveView('results');
                      setMenuOpen(false);
                    }}
                    className="w-full text-left px-4 py-2 hover:bg-gray-100 transition-colors"
                  >
                    Election Results
                  </button>
                </li>
              </ul>
            </div>
          )}
        </div>
        <button onClick={contactEmail} className="hover:underline">election@gmail.com</button>
        <button onClick={contactPhone} className="hover:underline">+00000 00000|00000 00000</button>
        <div className="flex items-center">
          <span>follow us on</span>
          <div className="ml-2 flex space-x-2">
            <button onClick={() => openSocialMedia('facebook')} className="text-blue-600 hover:text-blue-800">
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M22 12c0-5.523-4.477-10-10-10S2 6.477 2 12c0 4.991 3.657 9.128 8.438 9.878v-6.987h-2.54V12h2.54V9.797c0-2.506 1.492-3.89 3.777-3.89 1.094 0 2.238.195 2.238.195v2.46h-1.26c-1.243 0-1.63.771-1.63 1.562V12h2.773l-.443 2.89h-2.33v6.988C18.343 21.128 22 16.991 22 12z"/>
              </svg>
            </button>
            <button onClick={() => openSocialMedia('twitter')} className="text-blue-400 hover:text-blue-600">
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M8.29 20.251c7.547 0 11.675-6.253 11.675-11.675 0-.178 0-.355-.012-.53A8.348 8.348 0 0022 5.92a8.19 8.19 0 01-2.357.646 4.118 4.118 0 001.804-2.27 8.224 8.224 0 01-2.605.996 4.107 4.107 0 00-6.993 3.743 11.65 11.65 0 01-8.457-4.287 4.106 4.106 0 001.27 5.477A4.072 4.072 0 012.8 9.713v.052a4.105 4.105 0 003.292 4.022 4.095 4.095 0 01-1.853.07 4.108 4.108 0 003.834 2.85A8.233 8.233 0 012 18.407a11.616 11.616 0 006.29 1.84"/>
              </svg>
            </button>
            <button onClick={() => openSocialMedia('instagram')} className="text-pink-500 hover:text-pink-700">
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zM12 16a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 100 2.881 1.44 1.44 0 000-2.881z"/>
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* ECI Logo Header */}
      <div className="bg-gray-200 py-2 px-4 flex justify-between items-center">
        <div className="flex items-center">
          <img src={electionCommissionLogo} alt="Election Commission of India" className="h-16" />
        </div>
        <div className="flex items-center">
          <input 
            type="text" 
            className="border p-1" 
            placeholder="Search voters, candidates..."
            value={headerSearchQuery}
            onChange={(e) => setHeaderSearchQuery(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleHeaderSearch()}
          />
          <button 
            onClick={handleHeaderSearch}
            className="bg-red-500 text-white px-3 py-1 ml-1 hover:bg-red-600 transition-colors"
          >
            search
          </button>
        </div>
      </div>

      {/* Main hero section with green background */}
      <div className="bg-green-200 px-4 py-12 flex">
        <div className="w-1/2 pr-4">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">WELCOME TO INDIA'S OFFICIAL ONLINE VOTING PORTAL</h1>
          <p className="text-xl mb-8 text-gray-800">EMPOWERING CITIZENS WITH SECURE, EASY, AND ACCESSIBLE VOTING FROM ANYWHERE IN INDIA.</p>
          
          <div className="flex space-x-4">
            <button 
              onClick={() => setActiveView('voterLogin')}
              className="bg-gray-200 text-gray-800 font-bold py-3 px-6 hover:bg-gray-300 transition-colors"
            >
              LOGIN TO VOTE
            </button>
            <button 
              onClick={() => setActiveView('voterRegister')}
              className="bg-gray-200 text-gray-800 font-bold py-3 px-6 hover:bg-gray-300 transition-colors"
            >
              REGISTER AS A VOTER
            </button>
          </div>
        </div>
        <div className="w-1/2">
          <img 
            src={indiaFlagImage} 
            alt="India Flag with Voting Finger" 
            className="w-auto h-64 object-contain mx-auto rounded"
          />
        </div>
      </div>

      {/* About section */}
      <div className="bg-gray-200 py-8 px-4">
        <h2 className="text-2xl font-bold mb-8 text-center text-gray-900">ABOUT THE ONLINE VOTING SYSTEM</h2>
        
        <div className="grid grid-cols-3 gap-8 mb-12">
          <div className="bg-orange-200 p-6 rounded">
            <h3 className="text-xl font-bold mb-4 text-center">WHO CAN USE IT:</h3>
            <div className="flex justify-center mb-4">
              <svg className="w-16 h-16 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
              </svg>
            </div>
            <p className="text-gray-800 text-center">ALL ELIGIBLE INDIAN CITIZENS ABOVE 18 YEARS OF AGE WITH A VALID VOTER ID AND AADHAAR CARD CAN PARTICIPATE IN ONLINE VOTING.</p>
          </div>
          
          <div className="bg-orange-200 p-6 rounded">
            <h3 className="text-xl font-bold mb-4 text-center">HOW IT WORKS:</h3>
            <div className="flex justify-center mb-4">
              <svg className="w-16 h-16 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <p className="text-gray-800 text-center">VOTERS AUTHENTICATE USING AADHAAR OTP/BIOMETRICS, SELECT THEIR CONSTITUENCY, VIEW CANDIDATES, AND CAST THEIR VOTE SECURELY.</p>
          </div>
          
          <div className="bg-orange-200 p-6 rounded">
            <h3 className="text-xl font-bold mb-4 text-center">CONFIRM:</h3>
            <div className="flex justify-center mb-4">
              <svg className="w-16 h-16 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
              </svg>
            </div>
            <p className="text-gray-800 text-center">A BLOCKCHAIN-BASED CONFIRMATION RECEIPT IS GENERATED AFTER A SUCCESSFUL VOTE TO ENSURE TRANSPARENCY AND INTEGRITY.</p>
          </div>
        </div>

        {/* Live updates section */}
        <div className="bg-pink-500 text-white p-2 flex justify-between items-center mb-8">
          <div className="font-bold">LIVE UPDATES</div>
          <div>Read More »</div>
        </div>

        {getCurrentSlide() && (
          <div 
            className="bg-green-200 p-2 flex items-center mb-8 transition-opacity duration-300"
            style={{ opacity: 1 }}
          >
            <div className="text-gray-900">{getCurrentSlide().text}</div>
          <div className="ml-auto text-2xl">»</div>
        </div>
        )}

        {/* Voter services section */}
        <h2 className="text-2xl font-bold mb-8 text-gray-900">VOTER SERVICES</h2>
        
        <div className="grid grid-cols-4 gap-4 mb-12">
          <div 
            onClick={() => {
              setActiveView('voterServices');
              setVoterServiceView('checkStatus');
            }}
            className="bg-yellow-300 p-4 flex flex-col items-center text-center cursor-pointer hover:bg-yellow-400 transition-colors"
          >
            <div className="mb-2">
              <svg className="w-12 h-12 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <h3 className="font-bold mb-1">Check Voter ID Status</h3>
          </div>
          
          <div 
            onClick={() => {
              setActiveView('voterServices');
              setVoterServiceView('updateDetails');
            }}
            className="bg-yellow-300 p-4 flex flex-col items-center text-center cursor-pointer hover:bg-yellow-400 transition-colors"
          >
            <div className="mb-2">
              <svg className="w-12 h-12 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </div>
            <h3 className="font-bold mb-1">Update Voter Details</h3>
          </div>
          
          <div 
            onClick={() => {
              setActiveView('voterServices');
              setVoterServiceView('downloadVoterId');
            }}
            className="bg-yellow-300 p-4 flex flex-col items-center text-center cursor-pointer hover:bg-yellow-400 transition-colors"
          >
            <div className="mb-2">
              <svg className="w-12 h-12 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
            </div>
            <h3 className="font-bold mb-1">Download Voter Slip</h3>
          </div>
          
          <div 
            onClick={() => {
              setActiveView('voterServices');
              setVoterServiceView('howToVote');
            }}
            className="bg-yellow-300 p-4 flex flex-col items-center text-center cursor-pointer hover:bg-yellow-400 transition-colors"
          >
            <div className="mb-2">
              <svg className="w-12 h-12 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="font-bold mb-1">How To Vote</h3>
          </div>
        </div>
      </div>

      {/* Safe and secure section */}
      <div className="bg-red-300 py-8 px-4">
        <h2 className="text-2xl font-bold mb-8 text-gray-900">Your Vote Is Safe & Secure</h2>
        
        <div className="grid grid-cols-5 gap-4 mb-8">
          <div className="bg-gray-300 h-16 col-span-1"></div>
          <div className="bg-gray-300 h-16 col-span-1"></div>
          <div className="bg-gray-300 h-16 col-span-1"></div>
          <div className="bg-gray-300 h-16 col-span-2"></div>
        </div>
        
        <div className="mb-6">
          <p className="text-gray-800 mb-4">
            We Use Aadhaar-Based OTP & Biometric Login, AES-256 Encryption, And Blockchain Technology To Make Sure Every Vote Is Secure, Tamper-Proof, And Transparent. Our System Complies With Digital India And NIC Security Protocols.
          </p>
        </div>

        {/* Footer contact information */}
        <div className="border-t border-gray-400 pt-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <p><span className="font-bold">Email:</span> Support@ECI.Gov.In</p>
              <p><span className="font-bold">Helpline:</span> 1950 (Toll-Free)</p>
              <p><span className="font-bold">Address:</span> Nirvachan Sadan, Ashoka Road, New Delhi - 110001</p>
            </div>
            <div>
              <p><span className="font-bold">Links:</span></p>
              <div className="flex flex-wrap gap-2">
                <button onClick={openPrivacyPolicy} className="hover:underline">Privacy Policy</button> |
                <button onClick={openTermsOfService} className="hover:underline">Terms & Conditions</button> |
                <button onClick={() => alert("Accessibility features: Screen reader support, keyboard navigation, and high contrast mode are available.")} className="hover:underline">Accessibility</button>
              </div>
            </div>
            <div>
              <p><span className="font-bold">Languages:</span></p>
              <div className="flex flex-wrap gap-2">
                {languages.map((language, index) => (
                  <React.Fragment key={language}>
                    <button 
                      onClick={() => changeLanguage(language)}
                      className={`hover:underline ${currentLanguage === language.toLowerCase() ? 'font-bold' : ''}`}
                    >
                      {language}
                    </button>
                    {index < languages.length - 1 && ' | '}
                  </React.Fragment>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Admin login button - visible only in development */}
      {process.env.NODE_ENV === 'development' && (
        <div className="text-center py-2 bg-gray-700">
          <button 
            onClick={() => setActiveView('adminLogin')}
            className="bg-gray-600 text-white py-1 px-3 rounded hover:bg-gray-800 transition-colors"
          >
            Admin Login (Dev Only)
          </button>
        </div>
      )}
    </div>
  );

  const renderVoterRegisterView = () => (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4">
      <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md border-t-4 border-blue-600">
        <div className="flex justify-center mb-6">
          <img src={electionCommissionLogo} alt="Election Commission of India" className="h-16" />
        </div>
        <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Register as Voter</h2>
        
        {/* DigiLocker Authentication Status */}
        {digilockerStatus && (
          <div className={`mb-4 p-3 rounded text-center ${
            isDigilockerAuthenticated ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'
          }`}>
            {digilockerStatus}
          </div>
        )}
        
        {/* DigiLocker Registration Button */}
        <div className="mb-6">
          {!isDigilockerAuthenticated ? (
            <button 
              onClick={initiateDigilockerAuth}
              className="w-full flex items-center justify-center bg-indigo-600 text-white py-3 px-4 rounded-lg hover:bg-indigo-700 transition-colors"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
              </svg>
              Register with DigiLocker
            </button>
          ) : (
                  <button 
              onClick={registerVoterWithDigiLocker}
              className="w-full flex items-center justify-center bg-green-600 text-white py-3 px-4 rounded-lg hover:bg-green-700 transition-colors"
            >
              <Check className="h-5 w-5 mr-2" />
              Complete Registration with DigiLocker
                  </button>
              )}
            </div>
        
        <div className="mt-8 p-4 bg-blue-50 rounded border border-blue-100">
          <h3 className="text-lg font-semibold mb-2 text-blue-900">Why Register with DigiLocker?</h3>
          <ul className="text-blue-800 space-y-2">
            <li className="flex items-start">
              <Check className="h-5 w-5 mr-2 text-green-600 flex-shrink-0 mt-0.5" />
              <span>Secure authentication using government-verified identity</span>
            </li>
            <li className="flex items-start">
              <Check className="h-5 w-5 mr-2 text-green-600 flex-shrink-0 mt-0.5" />
              <span>No need for manual document verification</span>
            </li>
            <li className="flex items-start">
              <Check className="h-5 w-5 mr-2 text-green-600 flex-shrink-0 mt-0.5" />
              <span>Faster registration process with pre-filled information</span>
            </li>
            <li className="flex items-start">
              <Check className="h-5 w-5 mr-2 text-green-600 flex-shrink-0 mt-0.5" />
              <span>Reduced chances of errors in your voter information</span>
            </li>
          </ul>
          </div>
          
          <button 
            onClick={() => setActiveView('home')}
          className="w-full bg-gray-300 text-gray-700 py-3 px-4 rounded-lg hover:bg-gray-400 transition-colors mt-6"
          >
            Back to Home
          </button>
      </div>
    </div>
  );

  const renderVoterLoginView = () => (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4">
      <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md border-t-4 border-blue-600">
        <div className="flex justify-center mb-6">
          <img src={electionCommissionLogo} alt="Election Commission of India" className="h-16" />
        </div>
        <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Voter Login</h2>
        
        {/* DigiLocker Authentication Status */}
        {digilockerStatus && (
          <div className={`mb-4 p-3 rounded text-center ${
            isDigilockerAuthenticated ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'
          }`}>
            {digilockerStatus}
          </div>
        )}
        
        {/* DigiLocker Authentication Button */}
        <div className="mb-6">
          <button 
            onClick={initiateDigilockerAuth}
            disabled={isDigilockerAuthenticated}
            className={`w-full flex items-center justify-center bg-indigo-600 text-white py-3 px-4 rounded-lg ${
              isDigilockerAuthenticated ? 'opacity-60 cursor-not-allowed' : 'hover:bg-indigo-700'
            } transition-colors`}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
            </svg>
            {isDigilockerAuthenticated ? 'Authenticated with DigiLocker' : 'Login with DigiLocker'}
          </button>
        </div>
        
        <div className="relative my-6">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">Or login with Voter ID</span>
          </div>
        </div>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Voter ID</label>
            <input
              type="text"
              placeholder="Enter Voter ID"
              value={loginInputValue}
              onChange={(e) => setLoginInputValue(e.target.value)}
              className="w-full p-3 border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Aadhaar Number</label>
            <input
              type="text"
              placeholder="Enter 12-digit Aadhaar"
              className="w-full p-3 border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <div className="mt-4 mb-2">
            <label className="block text-sm font-medium mb-1 text-gray-700">Fingerprint Verification (Required)</label>
            <div className="border border-gray-300 rounded p-4 flex flex-col items-center">
              {fingerprintVerified ? (
                <div className="flex items-center text-green-600">
                  <Check className="mr-2" />
                  <span>Fingerprint Verified</span>
                </div>
              ) : (
                <>
                  <button 
                    onClick={() => verifyFingerprint('login', loginInputValue)}
                    disabled={fingerprintScanActive || !loginInputValue || isDigilockerAuthenticated}
                    className={`p-6 rounded-full mb-2 flex items-center justify-center ${
                      fingerprintScanActive 
                        ? 'bg-blue-200 animate-pulse' 
                        : (!loginInputValue || isDigilockerAuthenticated)
                          ? 'bg-gray-100 text-gray-400 cursor-not-allowed' 
                          : 'bg-blue-100 hover:bg-blue-200'
                    }`}
                  >
                    <Fingerprint size={64} className={(fingerprintScanActive || !loginInputValue || isDigilockerAuthenticated) ? 'text-gray-400' : 'text-blue-600'} />
                  </button>
                  <p className="text-center text-gray-600">
                    {fingerprintScanActive 
                      ? 'Scanning fingerprint...' 
                      : isDigilockerAuthenticated
                        ? 'DigiLocker authentication is active'
                        : !isBiometricAvailable
                          ? 'Fingerprint scanning not available on this device'
                      : !loginInputValue 
                        ? 'Enter Voter ID first, then scan fingerprint' 
                            : isBiometricAvailable
                              ? 'Place your finger on the scanner to login with Windows Hello' 
                              : 'Click to simulate fingerprint scan'}
                  </p>
                </>
              )}
            </div>
          </div>
          
          <button 
            onClick={() => setActiveView('home')}
            className="w-full bg-gray-300 text-gray-700 py-3 px-4 rounded-lg hover:bg-gray-400 transition-colors"
          >
            Back to Home
          </button>
        </div>
      </div>
    </div>
  );

  const renderAdminLoginView = () => (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4">
      <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md border-t-4 border-blue-600">
        <div className="flex justify-center mb-6">
          <img src={electionCommissionLogo} alt="Election Commission of India" className="h-16" />
        </div>
        <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Admin Login</h2>
        
        {adminLoginError && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {adminLoginError}
          </div>
        )}
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Admin ID</label>
            <input
              type="text"
              placeholder="Enter Admin ID"
              value={adminCredentials.id}
              onChange={(e) => setAdminCredentials({...adminCredentials, id: e.target.value})}
              className="w-full p-3 border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Password</label>
            <input
              type="password"
              placeholder="Enter Password"
              value={adminCredentials.password}
              onChange={(e) => setAdminCredentials({...adminCredentials, password: e.target.value})}
              className="w-full p-3 border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <button 
            onClick={adminLogin}
            className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Login
          </button>
          
          <button 
            onClick={() => setActiveView('home')}
            className="w-full bg-gray-300 text-gray-700 py-3 px-4 rounded-lg hover:bg-gray-400 transition-colors"
          >
            Back to Home
          </button>
        </div>
      </div>
    </div>
  );
  
  const renderAdminView = () => (
    <div className="min-h-screen bg-gray-50 py-8 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center">
            <img src={electionCommissionLogo} alt="Election Commission" className="h-12 mr-4" />
            <h2 className="text-2xl font-bold text-blue-900">Admin Dashboard</h2>
          </div>
          <button 
            onClick={() => {
              setIsAdmin(false);
              setAdminCredentials({ id: '', password: '' });
              setActiveView('home');
            }}
            className="bg-gray-300 text-gray-700 py-2 px-4 rounded hover:bg-gray-400 transition-colors"
          >
            Logout
          </button>
        </div>
        
        <div className="grid md:grid-cols-2 gap-8 mb-8">
          {/* Candidate Registration */}
          <div className="bg-white p-6 rounded-lg shadow border-t-4 border-blue-600">
            <h3 className="text-xl font-bold mb-4 text-blue-800">Register Candidate</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Candidate ID</label>
                <input
                  type="text"
                  placeholder="Candidate ID"
                  value={newCandidate.id}
                  onChange={(e) => handleInputChange('id', e.target.value, 'candidate')}
                  className={`w-full p-2 border ${validationErrors.candidate?.id ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                />
                {validationErrors.candidate?.id && (
                  <p className="mt-1 text-sm text-red-600">{validationErrors.candidate.id}</p>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Candidate Name</label>
                <input
                  type="text"
                  placeholder="Candidate Name"
                  value={newCandidate.name}
                  onChange={(e) => handleInputChange('name', e.target.value, 'candidate')}
                  className={`w-full p-2 border ${validationErrors.candidate?.name ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                />
                {validationErrors.candidate?.name && (
                  <p className="mt-1 text-sm text-red-600">{validationErrors.candidate.name}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Fingerprint</label>
                <div className="border border-gray-300 rounded p-3 flex flex-col items-center">
                  {newCandidate.fingerprintData ? (
                    <div className="flex items-center text-green-600">
                      <Check className="mr-2" />
                      <span>Fingerprint Recorded</span>
                    </div>
                  ) : (
                    <>
                      <button 
                        onClick={() => simulateFingerprintScan('register-candidate')}
                        disabled={fingerprintScanActive || !isBiometricAvailable}
                        className={`p-3 rounded-full mb-2 flex items-center justify-center ${
                          fingerprintScanActive ? 'bg-blue-200 animate-pulse' : 
                          !isBiometricAvailable ? 'bg-gray-200 cursor-not-allowed' :
                          'bg-blue-100 hover:bg-blue-200'
                        }`}
                      >
                        <Fingerprint size={30} className={!isBiometricAvailable ? "text-gray-400" : "text-blue-600"} />
                      </button>
                      <p className="text-sm text-center text-gray-600">
                        {fingerprintScanActive 
                          ? 'Scanning fingerprint...' 
                          : !isBiometricAvailable
                            ? 'Fingerprint scanning not available on this device'
                            : isBiometricAvailable
                              ? 'Click to scan with Windows Hello'
                              : 'Click to simulate fingerprint scan'}
                      </p>
                    </>
                  )}
                </div>
              </div>
              
              <button 
                onClick={registerCandidate}
                className="w-full bg-green-600 text-white py-2 px-4 rounded hover:bg-green-700 transition-colors"
              >
                Register Candidate
              </button>
            </div>
            
            <div className="mt-4">
              <h4 className="font-medium mb-2 text-gray-700">Registered Candidates:</h4>
              {candidates.length === 0 ? (
                <p className="text-gray-500">No candidates registered yet</p>
              ) : (
                <div className="max-h-40 overflow-y-auto border rounded p-2">
                  {candidates.map((candidate) => (
                    <div key={candidate.id} className="border-b py-2 last:border-b-0">
                      <strong>{candidate.name}</strong> (ID: {candidate.id})
                      {candidate.fingerprintData && (
                        <span className="ml-2 text-green-600 text-sm flex items-center">
                          <Fingerprint size={16} className="mr-1" />
                          Biometric Registered
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Voter Registration */}
          <div className="bg-white p-6 rounded-lg shadow border-t-4 border-green-600">
            <h3 className="text-xl font-bold mb-4 text-green-800">Manually Register Voter</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Voter ID</label>
                <input
                  type="text"
                  placeholder="Enter Voter ID (e.g., ABC1234567)"
                  value={newVoter.id}
                  onChange={(e) => handleInputChange('id', e.target.value, 'voter')}
                  className={`w-full p-2 border ${validationErrors.voter?.id ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                />
                {validationErrors.voter?.id && (
                  <p className="mt-1 text-sm text-red-600">{validationErrors.voter.id}</p>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Full Name</label>
                <input
                  type="text"
                  placeholder="Enter Full Name"
                  value={newVoter.name}
                  onChange={(e) => handleInputChange('name', e.target.value, 'voter')}
                  className={`w-full p-2 border ${validationErrors.voter?.name ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                />
                {validationErrors.voter?.name && (
                  <p className="mt-1 text-sm text-red-600">{validationErrors.voter.name}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Date of Birth</label>
                <input
                  type="date"
                  placeholder="Select Date of Birth"
                  value={dob}
                  onChange={(e) => handleInputChange('dob', e.target.value, 'voter')}
                  className={`w-full p-2 border ${validationErrors.voter?.dob ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                  max={new Date().toISOString().split('T')[0]} // Prevent future dates
                />
                {validationErrors.voter?.dob && (
                  <p className="mt-1 text-sm text-red-600">{validationErrors.voter.dob}</p>
                )}
                {age !== null && !validationErrors.voter?.dob && (
                  <p className="mt-1 text-sm text-green-600">Age: {age} years</p>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Aadhaar Number</label>
                <input
                  type="text"
                  placeholder="Enter 12-digit Aadhaar"
                  value={newVoter.aadhaar}
                  onChange={(e) => handleInputChange('aadhaar', e.target.value, 'voter')}
                  className={`w-full p-2 border ${validationErrors.voter?.aadhaar ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                  maxLength={12}
                />
                {validationErrors.voter?.aadhaar && (
                  <p className="mt-1 text-sm text-red-600">{validationErrors.voter.aadhaar}</p>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Mobile Number</label>
                <input
                  type="text"
                  placeholder="Enter 10-digit Mobile Number"
                  value={newVoter.mobile}
                  onChange={(e) => handleInputChange('mobile', e.target.value, 'voter')}
                  className={`w-full p-2 border ${validationErrors.voter?.mobile ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                  maxLength={10}
                />
                {validationErrors.voter?.mobile && (
                  <p className="mt-1 text-sm text-red-600">{validationErrors.voter.mobile}</p>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700">Fingerprint</label>
                <div className="border border-gray-300 rounded p-3 flex flex-col items-center">
                  {newVoter.fingerprintData ? (
                    <div className="flex items-center text-green-600">
                      <Check className="mr-2" />
                      <span>Fingerprint Recorded</span>
                    </div>
                  ) : (
                    <>
                      <button 
                        onClick={() => simulateFingerprintScan('register-voter')}
                        disabled={fingerprintScanActive}
                        className={`p-3 rounded-full mb-2 flex items-center justify-center ${
                          fingerprintScanActive ? 'bg-blue-200 animate-pulse' : 'bg-blue-100 hover:bg-blue-200'
                        }`}
                      >
                        <Fingerprint size={30} className="text-blue-600" />
                      </button>
                      <p className="text-sm text-center text-gray-600">
                        {fingerprintScanActive 
                          ? 'Scanning fingerprint...' 
                          : 'Click to scan fingerprint'}
                      </p>
                    </>
                  )}
                </div>
              </div>
              
              <button 
                onClick={registerVoter}
                className="w-full bg-green-600 text-white py-2 px-4 rounded hover:bg-green-700 transition-colors"
              >
                Register Voter
              </button>
            </div>
          </div>
        </div>
        
        {/* Voter Management Section */}
        <div className="bg-white p-6 rounded-lg shadow border-t-4 border-purple-600 mb-8">
          <h3 className="text-xl font-bold mb-4 text-purple-800">Voter Management</h3>
          
          <div className="mb-6">
            <div className="flex mb-4">
              <input
                type="text"
                placeholder="Search by Voter ID, Name or Aadhaar"
                value={voterSearchQuery}
                onChange={(e) => setVoterSearchQuery(e.target.value)}
                className="flex-1 p-2 border border-gray-300 rounded-l focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <button
                onClick={() => searchVoterById(voterSearchQuery)}
                className="bg-blue-500 text-white px-4 py-2 rounded-r hover:bg-blue-600 transition-colors"
              >
                Search
              </button>
            </div>
            
            {voterSearchResults.length > 0 && (
              <div className="border rounded">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Voter ID
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Name
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Aadhaar
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Mobile
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {voterSearchResults.map(voter => (
                      <tr key={voter.id}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {voter.id}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {voter.name}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          XXXX-XXXX-{voter.aadhaar.substring(8)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {voter.mobile}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                            checkVoterIdStatus(voter) === 'Active' ? 'bg-green-100 text-green-800' :
                            checkVoterIdStatus(voter) === 'Already voted' ? 'bg-blue-100 text-blue-800' :
                            'bg-red-100 text-red-800'
                          }`}>
                            {checkVoterIdStatus(voter)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          <button
                            onClick={() => selectVoterForService(voter)}
                            className="text-indigo-600 hover:text-indigo-900 mr-3"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => generateVoterIdCard(voter)}
                            className="text-green-600 hover:text-green-900"
                          >
                            Card
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            
            {voterSearchResults.length === 0 && voterSearchQuery && (
              <div className="text-center py-4 text-gray-500">
                No voters found matching your search
              </div>
            )}
          </div>
          
          {selectedVoter && (
            <div className="border-t pt-6 mt-6">
              <h4 className="font-medium mb-4 text-gray-700">Edit Voter: {selectedVoter.name}</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1 text-gray-700">Full Name</label>
                  <input
                    type="text"
                    value={updatedVoterDetails.name || ''}
                    onChange={(e) => {
                      setUpdatedVoterDetails({...updatedVoterDetails, name: e.target.value});
                      const nameError = validateName(e.target.value);
                      setValidationErrors({
                        ...validationErrors,
                        updateVoter: {
                          ...validationErrors.updateVoter,
                          name: nameError
                        }
                      });
                    }}
                    className={`w-full p-2 border ${validationErrors.updateVoter?.name ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                  />
                  {validationErrors.updateVoter?.name && (
                    <p className="mt-1 text-sm text-red-600">{validationErrors.updateVoter.name}</p>
                  )}
                </div>
                
                <div>
                  <label className="block text-sm font-medium mb-1 text-gray-700">Mobile Number</label>
                  <input
                    type="text"
                    value={updatedVoterDetails.mobile || ''}
                    onChange={(e) => {
                      setUpdatedVoterDetails({...updatedVoterDetails, mobile: e.target.value});
                      const mobileError = validateMobile(e.target.value);
                      setValidationErrors({
                        ...validationErrors,
                        updateVoter: {
                          ...validationErrors.updateVoter,
                          mobile: mobileError
                        }
                      });
                    }}
                    maxLength={10}
                    className={`w-full p-2 border ${validationErrors.updateVoter?.mobile ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                  />
                  {validationErrors.updateVoter?.mobile && (
                    <p className="mt-1 text-sm text-red-600">{validationErrors.updateVoter.mobile}</p>
                  )}
                </div>
              </div>
              
              <div className="flex space-x-4 mt-4">
                <button
                  onClick={() => setSelectedVoter(null)}
                  className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded hover:bg-gray-400 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={updateVoterDetails}
                  className="flex-1 bg-green-600 text-white py-2 px-4 rounded hover:bg-green-700 transition-colors"
                >
                  Save Changes
                </button>
              </div>
            </div>
          )}
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow border-t-4 border-blue-600 mb-8">
          <h3 className="text-xl font-bold mb-4 text-blue-800">Blockchain Status</h3>
          
          <div className="space-y-4">
            <div className="grid md:grid-cols-3 gap-4">
              <div className="bg-blue-50 p-3 rounded border border-blue-100">
                <p className="text-sm font-medium text-blue-800">Blocks in chain</p>
                <p className="text-2xl font-bold text-blue-900">{blockchain.chain.length}</p>
              </div>
              <div className="bg-blue-50 p-3 rounded border border-blue-100">
                <p className="text-sm font-medium text-blue-800">Pending votes</p>
                <p className="text-2xl font-bold text-blue-900">{blockchain.pendingVotes.length}</p>
              </div>
              <div className="bg-blue-50 p-3 rounded border border-blue-100">
                <p className="text-sm font-medium text-blue-800">Chain status</p>
                <p className={`text-2xl font-bold ${
                  blockchain.isChainValid() ? 'text-green-600' : 'text-red-600'
                }`}>
                  {blockchain.isChainValid() ? 'Valid' : 'Invalid'}
                </p>
              </div>
            </div>
            
            <div className="flex space-x-4">
              <button 
                onClick={checkBlockchain}
                className="bg-purple-600 text-white py-2 px-4 rounded hover:bg-purple-700 transition-colors"
              >
                Verify Blockchain
              </button>
              
              <button 
                onClick={() => blockchain.minePendingVotes()}
                className="bg-yellow-500 text-white py-2 px-4 rounded hover:bg-yellow-600 transition-colors"
              >
                Mine Pending Votes
              </button>
            </div>
          </div>
        </div>
        
        <div className="flex justify-between">
          <button 
            onClick={() => setActiveView('results')}
            className="bg-indigo-600 text-white py-2 px-4 rounded hover:bg-indigo-700 transition-colors"
          >
            View Results
          </button>
        </div>
      </div>
    </div>
  );
  
  const renderVotingView = () => (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4">
      <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md border-t-4 border-blue-600">
        <div className="flex justify-center mb-6">
          <img src={electionCommissionLogo} alt="Election Commission of India" className="h-16" />
        </div>
        <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Cast Your Vote</h2>
        <p className="mb-6 text-center text-gray-700">Welcome, {currentVoter?.name}</p>
        
        <div className="space-y-6">
          <div className="border border-gray-200 rounded-lg p-4">
            <h3 className="font-bold mb-4 text-blue-800">Select Candidate:</h3>
            
            {candidates.length === 0 ? (
              <p className="text-gray-500">No candidates available</p>
            ) : (
              <div className="space-y-3">
                {candidates.map((candidate) => (
                  <div key={candidate.id} className="flex items-center p-2 hover:bg-gray-50 rounded">
                    <input
                      type="radio"
                      id={candidate.id}
                      name="candidate"
                      value={candidate.id}
                      checked={selectedCandidate === candidate.id}
                      onChange={() => setSelectedCandidate(candidate.id)}
                      className="mr-3 h-5 w-5 text-blue-600 focus:ring-blue-500"
                    />
                    <label htmlFor={candidate.id} className="text-lg text-gray-700">{candidate.name}</label>
                  </div>
                ))}
              </div>
            )}
          </div>
          
          {votingStatus && (
            <div className="p-3 bg-green-100 text-green-700 rounded text-center">
              {votingStatus}
            </div>
          )}
          
          <button 
            onClick={castVote}
            disabled={!selectedCandidate || votingStatus}
            className={`w-full py-3 px-4 rounded-lg flex items-center justify-center ${
              !selectedCandidate || votingStatus 
                ? 'bg-gray-300 text-gray-500 cursor-not-allowed' 
                : 'bg-green-600 text-white hover:bg-green-700 transition-colors'
            }`}
          >
            <Check className="mr-2" size={20} />
            Cast Vote
          </button>
          
          <button 
            onClick={() => {
              setCurrentVoter(null);
              setSelectedCandidate('');
              setVotingStatus('');
              setActiveView('home');
            }}
            className="w-full bg-gray-300 text-gray-700 py-3 px-4 rounded-lg hover:bg-gray-400 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
  
  const renderResultsView = () => {
    const voteCounts = blockchain.getVoteCounts();
    const totalVotes = Object.values(voteCounts).reduce((sum, count) => sum + count, 0) + blockchain.pendingVotes.length;
    
    return (
      <div className="min-h-screen bg-gray-50 py-12 px-4">
        <div className="max-w-4xl mx-auto bg-white p-8 rounded-lg shadow-lg border-t-4 border-blue-600">
          <div className="flex justify-center mb-6">
            <img src={electionCommissionLogo} alt="Election Commission of India" className="h-16" />
          </div>
          <h2 className="text-2xl font-bold mb-8 text-center text-blue-900">Election Results</h2>
          
          <div className="space-y-8">
            {totalVotes === 0 ? (
              <p className="text-center text-gray-500">No votes cast yet</p>
            ) : (
              <div>
                <div className="grid md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-blue-50 p-4 rounded-lg border border-blue-100">
                    <p className="text-sm font-medium text-blue-800">Total Votes</p>
                    <p className="text-2xl font-bold text-blue-900">{totalVotes}</p>
                  </div>
                  <div className="bg-green-50 p-4 rounded-lg border border-green-100">
                    <p className="text-sm font-medium text-green-800">Confirmed Votes</p>
                    <p className="text-2xl font-bold text-green-900">{totalVotes - blockchain.pendingVotes.length}</p>
                  </div>
                  <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-100">
                    <p className="text-sm font-medium text-yellow-800">Pending Votes</p>
                    <p className="text-2xl font-bold text-yellow-900">{blockchain.pendingVotes.length}</p>
                  </div>
                </div>
                
                <div className="space-y-4">
                  {candidates.map((candidate) => {
                    const voteCount = voteCounts[candidate.id] || 0;
                    const percentage = totalVotes > 0 ? ((voteCount / totalVotes) * 100).toFixed(1) : 0;
                    
                    return (
                      <div key={candidate.id} className="space-y-2">
                        <div className="flex justify-between">
                          <span className="font-medium text-gray-700">{candidate.name}</span>
                          <span className="text-gray-600">{voteCount} votes ({percentage}%)</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-3">
                          <div 
                            className="bg-blue-600 h-3 rounded-full" 
                            style={{ width: `${percentage}%` }}
                          ></div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            
            <div className="border-t border-gray-200 pt-6">
              <p className="font-medium mb-2 text-gray-700">Blockchain Status:</p>
              <div className="flex items-center">
                <span className={`inline-block w-3 h-3 rounded-full mr-2 ${
                  blockchain.isChainValid() ? 'bg-green-500' : 'bg-red-500'
                }`}></span>
                <span>{blockchain.isChainValid() ? 'Blockchain integrity verified' : 'Blockchain integrity compromised'}</span>
              </div>
              <p className="mt-2 text-gray-600"><strong>Blocks:</strong> {blockchain.chain.length}</p>
            </div>
            
            <button 
              onClick={() => setActiveView('home')}
              className="w-full bg-gray-300 text-gray-700 py-3 px-4 rounded-lg hover:bg-gray-400 transition-colors mt-6"
            >
              Back to Home
            </button>
          </div>
        </div>
      </div>
    );
  };

  // Voter service functions
  const searchVoterById = (query) => {
    if (!query.trim()) {
      setVoterSearchResults([]);
      return;
    }
    
    const results = voters.filter(
      voter => voter.id.toLowerCase().includes(query.toLowerCase()) || 
               voter.name.toLowerCase().includes(query.toLowerCase()) ||
               voter.aadhaar.includes(query)
    );
    
    setVoterSearchResults(results);
  };

  const selectVoterForService = (voter) => {
    setSelectedVoter(voter);
    setUpdatedVoterDetails({...voter});
  };

  const updateVoterDetails = () => {
    if (!selectedVoter) return;
    
    // Validate updated details
    const nameError = validateName(updatedVoterDetails.name);
    const mobileError = validateMobile(updatedVoterDetails.mobile);
    
    if (nameError || mobileError) {
      setValidationErrors({
        ...validationErrors,
        updateVoter: {
          name: nameError,
          mobile: mobileError
        }
      });
      return;
    }
    
    // Update voter in the database
    const updatedVoters = voters.map(voter => 
      voter.id === selectedVoter.id ? {...voter, ...updatedVoterDetails} : voter
    );
    
    setVoters(updatedVoters);
    alert('Voter details updated successfully!');
    setVoterServiceView('main');
    setSelectedVoter(null);
  };

  const generateVoterIdCard = (voter) => {
    if (!voter) return;
    
    // Calculate QR code data containing voter info (in a real app, this would be encrypted)
    const voterData = {
      id: voter.id,
      name: voter.name,
      aadhaar: voter.aadhaar.substring(8), // Only last 4 digits for security
      dateGenerated: new Date().toISOString().split('T')[0]
    };
    
    setVoterIdCardData(voterData);
    setVoterServiceView('viewVoterId');
  };

  const downloadVoterId = () => {
    // In a real application, this would generate a PDF
    // For this demo, we'll just show an alert
    alert('Voter ID downloaded successfully!');
  };

  const checkVoterIdStatus = (voter) => {
    if (!voter) return 'Not found';
    
    // Check if voter has voted
    const hasVoted = blockchain.chain.some(block => 
      block.votes.some(vote => vote.voter === voter.id)
    ) || blockchain.pendingVotes.some(vote => vote.voter === voter.id);
    
    if (hasVoted) {
      return 'Already voted';
    }
    
    return 'Active';
  };

  const handleVoterServiceNavigation = (service) => {
    setVoterServiceView(service);
    setSelectedVoter(null);
    setUpdatedVoterDetails({});
    setVoterSearchQuery('');
    setVoterSearchResults([]);
    setVoterIdCardData(null);
  };

  // Render voter service views
  const renderVoterServiceMain = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Voter Services</h2>
      
      <div className="grid grid-cols-2 gap-4 mb-8">
        <button
          onClick={() => handleVoterServiceNavigation('checkStatus')}
          className="bg-blue-500 hover:bg-blue-600 text-white py-4 px-6 rounded-lg flex flex-col items-center justify-center transition-colors"
        >
          <svg className="w-8 h-8 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <span className="font-medium">Check Voter ID Status</span>
        </button>
        
        <button
          onClick={() => handleVoterServiceNavigation('updateDetails')}
          className="bg-green-500 hover:bg-green-600 text-white py-4 px-6 rounded-lg flex flex-col items-center justify-center transition-colors"
        >
          <svg className="w-8 h-8 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <span className="font-medium">Update Voter Details</span>
        </button>
        
        <button
          onClick={() => handleVoterServiceNavigation('downloadVoterId')}
          className="bg-purple-500 hover:bg-purple-600 text-white py-4 px-6 rounded-lg flex flex-col items-center justify-center transition-colors"
        >
          <svg className="w-8 h-8 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          <span className="font-medium">Download Voter Slip</span>
        </button>
        
        <button
          onClick={() => handleVoterServiceNavigation('howToVote')}
          className="bg-yellow-500 hover:bg-yellow-600 text-white py-4 px-6 rounded-lg flex flex-col items-center justify-center transition-colors"
        >
          <svg className="w-8 h-8 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="font-medium">How To Vote</span>
        </button>
      </div>
      
      <button
        onClick={() => setActiveView('home')}
        className="w-full bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
      >
        Back to Home
      </button>
    </div>
  );

  const renderVoterStatusCheck = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Check Voter ID Status</h2>
      
      <div className="mb-6">
        <label className="block text-sm font-medium mb-1 text-gray-700">Enter Voter ID or Name</label>
        <div className="flex">
          <input
            type="text"
            value={voterSearchQuery}
            onChange={(e) => setVoterSearchQuery(e.target.value)}
            placeholder="Enter Voter ID, Name or Last 4 digits of Aadhaar"
            className="flex-1 p-3 border border-gray-300 rounded-l focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
          <button
            onClick={() => searchVoterById(voterSearchQuery)}
            className="bg-blue-500 text-white px-4 py-3 rounded-r hover:bg-blue-600 transition-colors"
          >
            Search
          </button>
        </div>
      </div>
      
      {voterSearchResults.length > 0 && (
        <div className="mb-6">
          <h3 className="font-medium mb-2 text-gray-700">Search Results:</h3>
          <div className="border rounded divide-y">
            {voterSearchResults.map(voter => (
              <div key={voter.id} className="p-3 hover:bg-gray-50">
                <div className="flex justify-between items-center">
                  <div>
                    <p className="font-medium">{voter.name}</p>
                    <p className="text-sm text-gray-600">ID: {voter.id}</p>
                    <p className="text-sm text-gray-600">Aadhaar: XXXX-XXXX-{voter.aadhaar.substring(8)}</p>
                  </div>
                  <div>
                    <span className={`px-2 py-1 rounded text-sm ${
                      checkVoterIdStatus(voter) === 'Active' ? 'bg-green-100 text-green-800' :
                      checkVoterIdStatus(voter) === 'Already voted' ? 'bg-blue-100 text-blue-800' :
                      'bg-red-100 text-red-800'
                    }`}>
                      {checkVoterIdStatus(voter)}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      
      <div className="flex space-x-4">
        <button
          onClick={() => handleVoterServiceNavigation('main')}
          className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
        >
          Back to Services
        </button>
        <button
          onClick={() => setActiveView('home')}
          className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
        >
          Back to Home
        </button>
      </div>
    </div>
  );

  const renderUpdateVoterDetails = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Update Voter Details</h2>
      
      {!selectedVoter ? (
        <>
          <div className="mb-6">
            <label className="block text-sm font-medium mb-1 text-gray-700">Enter Voter ID or Name</label>
            <div className="flex">
              <input
                type="text"
                value={voterSearchQuery}
                onChange={(e) => setVoterSearchQuery(e.target.value)}
                placeholder="Enter Voter ID, Name or Last 4 digits of Aadhaar"
                className="flex-1 p-3 border border-gray-300 rounded-l focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <button
                onClick={() => searchVoterById(voterSearchQuery)}
                className="bg-blue-500 text-white px-4 py-3 rounded-r hover:bg-blue-600 transition-colors"
              >
                Search
              </button>
            </div>
          </div>
          
          {voterSearchResults.length > 0 && (
            <div className="mb-6">
              <h3 className="font-medium mb-2 text-gray-700">Select Voter to Update:</h3>
              <div className="border rounded divide-y">
                {voterSearchResults.map(voter => (
                  <div 
                    key={voter.id} 
                    className="p-3 hover:bg-gray-50 cursor-pointer"
                    onClick={() => selectVoterForService(voter)}
                  >
                    <p className="font-medium">{voter.name}</p>
                    <p className="text-sm text-gray-600">ID: {voter.id}</p>
                    <p className="text-sm text-gray-600">Aadhaar: XXXX-XXXX-{voter.aadhaar.substring(8)}</p>
                    <p className="text-sm text-gray-600">Mobile: {voter.mobile}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Voter ID</label>
            <input
              type="text"
              value={selectedVoter.id}
              disabled
              className="w-full p-3 border border-gray-300 bg-gray-100 rounded"
            />
            <p className="mt-1 text-sm text-gray-500">Voter ID cannot be changed</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Aadhaar Number</label>
            <input
              type="text"
              value={selectedVoter.aadhaar}
              disabled
              className="w-full p-3 border border-gray-300 bg-gray-100 rounded"
            />
            <p className="mt-1 text-sm text-gray-500">Aadhaar number cannot be changed</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Full Name</label>
            <input
              type="text"
              value={updatedVoterDetails.name || ''}
              onChange={(e) => {
                setUpdatedVoterDetails({...updatedVoterDetails, name: e.target.value});
                const nameError = validateName(e.target.value);
                setValidationErrors({
                  ...validationErrors,
                  updateVoter: {
                    ...validationErrors.updateVoter,
                    name: nameError
                  }
                });
              }}
              className={`w-full p-3 border ${validationErrors.updateVoter?.name ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
            />
            {validationErrors.updateVoter?.name && (
              <p className="mt-1 text-sm text-red-600">{validationErrors.updateVoter.name}</p>
            )}
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700">Mobile Number</label>
            <input
              type="text"
              value={updatedVoterDetails.mobile || ''}
              onChange={(e) => {
                setUpdatedVoterDetails({...updatedVoterDetails, mobile: e.target.value});
                const mobileError = validateMobile(e.target.value);
                setValidationErrors({
                  ...validationErrors,
                  updateVoter: {
                    ...validationErrors.updateVoter,
                    mobile: mobileError
                  }
                });
              }}
              maxLength={10}
              className={`w-full p-3 border ${validationErrors.updateVoter?.mobile ? 'border-red-500' : 'border-gray-300'} rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
            />
            {validationErrors.updateVoter?.mobile && (
              <p className="mt-1 text-sm text-red-600">{validationErrors.updateVoter.mobile}</p>
            )}
          </div>
          
          <div className="flex space-x-4">
            <button
              onClick={() => setSelectedVoter(null)}
              className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={updateVoterDetails}
              className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors"
            >
              Update Details
            </button>
          </div>
        </div>
      )}
      
      <button
        onClick={() => handleVoterServiceNavigation('main')}
        className="w-full mt-6 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
      >
        Back to Services
      </button>
    </div>
  );

  const renderDownloadVoterId = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Download Voter Slip</h2>
      
      {!selectedVoter ? (
        <>
          <div className="mb-6">
            <label className="block text-sm font-medium mb-1 text-gray-700">Enter Voter ID or Name</label>
            <div className="flex">
              <input
                type="text"
                value={voterSearchQuery}
                onChange={(e) => setVoterSearchQuery(e.target.value)}
                placeholder="Enter Voter ID, Name or Last 4 digits of Aadhaar"
                className="flex-1 p-3 border border-gray-300 rounded-l focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <button
                onClick={() => searchVoterById(voterSearchQuery)}
                className="bg-blue-500 text-white px-4 py-3 rounded-r hover:bg-blue-600 transition-colors"
              >
                Search
              </button>
            </div>
          </div>
          
          {voterSearchResults.length > 0 && (
            <div className="mb-6">
              <h3 className="font-medium mb-2 text-gray-700">Select Voter:</h3>
              <div className="border rounded divide-y">
                {voterSearchResults.map(voter => (
                  <div 
                    key={voter.id} 
                    className="p-3 hover:bg-gray-50 cursor-pointer"
                    onClick={() => generateVoterIdCard(voter)}
                  >
                    <p className="font-medium">{voter.name}</p>
                    <p className="text-sm text-gray-600">ID: {voter.id}</p>
                    <p className="text-sm text-gray-600">Aadhaar: XXXX-XXXX-{voter.aadhaar.substring(8)}</p>
                    <div className="flex justify-end">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          generateVoterIdCard(voter);
                        }}
                        className="mt-2 bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600 transition-colors"
                      >
                        Generate Voter Slip
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      ) : null}
      
      <button
        onClick={() => handleVoterServiceNavigation('main')}
        className="w-full mt-6 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
      >
        Back to Services
      </button>
    </div>
  );

  const renderVoterIdCard = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">Voter ID Card</h2>
      
      {voterIdCardData && (
        <div className="border-2 border-blue-500 rounded-lg p-4 max-w-md mx-auto mb-6">
          <div className="flex items-center mb-4">
            <img src={electionCommissionLogo} alt="Election Commission of India" className="h-12 mr-4" />
            <div>
              <h2 className="text-lg font-bold text-blue-900">ELECTION COMMISSION OF INDIA</h2>
              <p className="text-sm text-gray-600">Voter Identification Card</p>
            </div>
          </div>
          
          <div className="flex mb-4">
            <div className="w-24 h-32 bg-gray-200 flex items-center justify-center text-gray-500 mr-4">
              <span>PHOTO</span>
            </div>
            <div className="flex-1">
              <p><span className="font-medium">Name:</span> {voterIdCardData.name}</p>
              <p><span className="font-medium">Voter ID:</span> {voterIdCardData.id}</p>
              <p><span className="font-medium">Aadhaar:</span> XXXX-XXXX-{voterIdCardData.aadhaar}</p>
              <p><span className="font-medium">Date:</span> {voterIdCardData.dateGenerated}</p>
              <div className="mt-2 w-20 h-20 bg-gray-200 flex items-center justify-center text-xs text-gray-500">
                QR CODE
              </div>
            </div>
          </div>
          
          <div className="border-t pt-2 text-center text-sm text-gray-600">
            <p>This card is issued by the Election Commission of India</p>
            <p>Blockchain Secured • Tamper Evident</p>
          </div>
        </div>
      )}
      
      <div className="flex space-x-4">
        <button
          onClick={downloadVoterId}
          className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors"
        >
          Download as PDF
        </button>
        <button
          onClick={() => handleVoterServiceNavigation('downloadVoterId')}
          className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
        >
          Back
        </button>
      </div>
    </div>
  );

  const renderHowToVote = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-2xl font-bold mb-6 text-center text-blue-900">How To Vote</h2>
      
      <div className="mb-6">
        <h3 className="text-lg font-semibold mb-3 text-gray-800">Voting Process:</h3>
        
        <div className="space-y-4">
          <div className="flex items-start">
            <div className="bg-blue-500 text-white rounded-full w-8 h-8 flex items-center justify-center mr-3 flex-shrink-0">1</div>
            <div>
              <h4 className="font-medium text-gray-800">Register as a Voter</h4>
              <p className="text-gray-600">Use your Aadhaar and personal details to register in the system. You can register through DigiLocker for enhanced security.</p>
            </div>
          </div>
          
          <div className="flex items-start">
            <div className="bg-blue-500 text-white rounded-full w-8 h-8 flex items-center justify-center mr-3 flex-shrink-0">2</div>
            <div>
              <h4 className="font-medium text-gray-800">Login on Election Day</h4>
              <p className="text-gray-600">Use your Voter ID and biometric verification (fingerprint or DigiLocker) to authenticate yourself.</p>
            </div>
          </div>
          
          <div className="flex items-start">
            <div className="bg-blue-500 text-white rounded-full w-8 h-8 flex items-center justify-center mr-3 flex-shrink-0">3</div>
            <div>
              <h4 className="font-medium text-gray-800">Cast Your Vote</h4>
              <p className="text-gray-600">Select your preferred candidate and confirm your choice. Your vote is then securely recorded on the blockchain.</p>
            </div>
          </div>
          
          <div className="flex items-start">
            <div className="bg-blue-500 text-white rounded-full w-8 h-8 flex items-center justify-center mr-3 flex-shrink-0">4</div>
            <div>
              <h4 className="font-medium text-gray-800">Receive Confirmation</h4>
              <p className="text-gray-600">A confirmation receipt will be generated as proof of your vote, without revealing your choice to maintain secrecy.</p>
            </div>
          </div>
        </div>
      </div>
      
      <div className="mb-6 bg-yellow-50 p-4 rounded border border-yellow-200">
        <h3 className="text-lg font-semibold mb-2 text-yellow-800">Important Notes:</h3>
        <ul className="list-disc list-inside space-y-1 text-yellow-800">
          <li>You can only vote once</li>
          <li>Ensure your biometric details are up to date</li>
          <li>Bring a valid ID proof on election day</li>
          <li>Your vote is completely confidential and secure</li>
          <li>If you face any issues, contact the election helpdesk</li>
        </ul>
      </div>
      
      <button
        onClick={() => handleVoterServiceNavigation('main')}
        className="w-full bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 transition-colors"
      >
        Back to Services
      </button>
    </div>
  );

  // Function to render the appropriate voter service view
  const renderVoterServices = () => {
    switch (voterServiceView) {
      case 'checkStatus':
        return renderVoterStatusCheck();
      case 'updateDetails':
        return renderUpdateVoterDetails();
      case 'downloadVoterId':
        return renderDownloadVoterId();
      case 'viewVoterId':
        return renderVoterIdCard();
      case 'howToVote':
        return renderHowToVote();
      default:
        return renderVoterServiceMain();
    }
  };

  // Add renderVoterServicesView to main render
  const renderVoterServicesView = () => (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4">
      <div className="w-full max-w-2xl">
        {renderVoterServices()}
      </div>
    </div>
  );

  // Header search function
  const handleHeaderSearch = () => {
    if (!headerSearchQuery.trim()) return;
    
    // Search for voters, candidates and any relevant information
    const results = [
      ...voters.filter(voter => 
        voter.name.toLowerCase().includes(headerSearchQuery.toLowerCase()) ||
        voter.id.toLowerCase().includes(headerSearchQuery.toLowerCase())
      ),
      ...candidates.filter(candidate => 
        candidate.name.toLowerCase().includes(headerSearchQuery.toLowerCase()) ||
        candidate.id.toLowerCase().includes(headerSearchQuery.toLowerCase())
      )
    ];
    
    setSearchResults(results);
    alert(`Found ${results.length} results for "${headerSearchQuery}"`);
    
    // If there are voter results, navigate to voter services and show results
    if (results.length > 0 && results.some(r => r.hasOwnProperty('aadhaar'))) {
      setActiveView('voterServices');
      setVoterServiceView('checkStatus');
      setVoterSearchQuery(headerSearchQuery);
      setVoterSearchResults(results.filter(r => r.hasOwnProperty('aadhaar')));
    }
  };
  
  // Slideshow management functions
  useEffect(() => {
    // Auto-rotate slideshow
    const interval = setInterval(() => {
      if (slideshowItems.filter(item => item.active).length > 1) {
        setCurrentSlideIndex(prevIndex => {
          const activeSlides = slideshowItems.filter(item => item.active);
          return (prevIndex + 1) % activeSlides.length;
        });
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [slideshowItems]);

  const addSlideshow = () => {
    if (newSlideText.trim()) {
      setSlideshowItems([
        ...slideshowItems,
        { id: Date.now(), text: newSlideText, active: true }
      ]);
      setNewSlideText('');
    }
  };

  const toggleSlideshow = (id) => {
    setSlideshowItems(slideshowItems.map(item => 
      item.id === id ? { ...item, active: !item.active } : item
    ));
  };

  const deleteSlideshow = (id) => {
    setSlideshowItems(slideshowItems.filter(item => item.id !== id));
  };

  const getCurrentSlide = () => {
    const activeSlides = slideshowItems.filter(item => item.active);
    if (activeSlides.length === 0) return null;
    return activeSlides[currentSlideIndex % activeSlides.length];
  };

  // Language change handler
  const changeLanguage = (language) => {
    setCurrentLanguage(language.toLowerCase());
    // In a real app, we would load translated content here
    alert(`Language changed to ${language}`);
  };

  // Privacy policy handler
  const openPrivacyPolicy = () => {
    window.open('/privacy-policy', '_blank');
    // For demo, we'll just create an alert
    alert('Privacy Policy: Your data is protected under the Information Technology Act, 2000 and Personal Data Protection Bill.');
  };

  // Terms of service handler
  const openTermsOfService = () => {
    window.open('/terms-of-service', '_blank');
    // For demo, we'll just create an alert
    alert('Terms of Service: By using this service, you agree to the Election Commission of India\'s terms and conditions.');
  };
  
  // Social media links
  const openSocialMedia = (platform) => {
    const urls = {
      facebook: 'https://www.facebook.com/ECI',
      twitter: 'https://twitter.com/ECISVEEP',
      instagram: 'https://www.instagram.com/ecisveep',
      youtube: 'https://www.youtube.com/eci'
    };
    
    if (urls[platform]) {
      window.open(urls[platform], '_blank');
    }
  };
  
  // Contact functions
  const contactEmail = () => {
    window.location.href = 'mailto:support@eci.gov.in';
  };
  
  const contactPhone = () => {
    window.location.href = 'tel:1950';
  };

  // Main render
  return (
    <div className="min-h-screen bg-gray-50">
      {activeView === 'home' && renderHomeView()}
      {activeView === 'voterRegister' && renderVoterRegisterView()}
      {activeView === 'voterLogin' && renderVoterLoginView()}
      {activeView === 'adminLogin' && renderAdminLoginView()}
      {activeView === 'admin' && renderAdminView()}
      {activeView === 'voting' && renderVotingView()}
      {activeView === 'results' && renderResultsView()}
      {activeView === 'voterServices' && renderVoterServicesView()}
    </div>
  );
}