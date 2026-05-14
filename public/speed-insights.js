/**
 * Vercel Speed Insights initialization
 * Official implementation following Vercel documentation
 * https://vercel.com/docs/speed-insights/quickstart
 */

// Initialize Speed Insights queue
window.si = window.si || function () { 
  (window.siq = window.siq || []).push(arguments); 
};

// Load the official Vercel Speed Insights script
// This script is automatically provided by Vercel when Speed Insights is enabled in the dashboard
const script = document.createElement('script');
script.defer = true;
script.src = '/_vercel/speed-insights/script.js';

document.head.appendChild(script);
