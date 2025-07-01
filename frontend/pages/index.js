import { useState } from 'react';
import Head from 'next/head';
import styles from '../styles/Home.module.css';
import Navbar from '../components/Navbar';
import { useAuth } from '../firebase/AuthContext';

export default function Home() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [debug, setDebug] = useState(null);
  const { currentUser } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);
    setDebug(null);

    try {
      // Ensure URL has a scheme
      let formattedUrl = url;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        formattedUrl = 'http://' + url;
      }

      console.log('Submitting URL:', formattedUrl);
      
      // Use the ApiService instead of direct fetch
      const data = await window.ApiService.predictUrl(formattedUrl);
      
      console.log('Response data:', data);
      
      if (data.status === 'error') {
        throw new Error(data.message || 'Error analyzing URL');
      }

      setResult(data);
    } catch (err) {
      console.error('Error:', err);
      setError(err.message || 'Failed to analyze URL. The service might be unavailable.');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score) => {
    if (score < 30) return '#4caf50'; // Green
    if (score < 70) return '#ff9800'; // Orange
    return '#f44336'; // Red
  };

  return (
    <div className={styles.container}>
      <Head>
        <title>URL Fraud Detection</title>
        <meta name="description" content="Detect potential fraud in URLs" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <Navbar />

      <main className={styles.main}>
        <h1 className={styles.title}>
          URL Fraud Detection
        </h1>

        <p className={styles.description}>
          {currentUser ? `Welcome, ${currentUser.displayName || currentUser.email}!` : 'Enter a URL to analyze for potential fraud'}
        </p>

        <form onSubmit={handleSubmit} className={styles.form}>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            required
          />
          <button 
            type="submit" 
            className={styles.button}
            disabled={loading}
          >
            {loading ? 'Analyzing...' : 'Analyze URL'}
          </button>
        </form>

        {error && (
          <div className={styles.error}>
            <p>{error}</p>
            {debug && (
              <details>
                <summary>Debug Information</summary>
                <pre>{JSON.stringify(debug, null, 2)}</pre>
              </details>
            )}
          </div>
        )}

        {result && (
          <div className={styles.result}>
            <h2>Analysis Results</h2>
            
            <div className={styles.scoreContainer}>
              <div className={styles.scoreCircle} style={{ 
                backgroundColor: getRiskColor(result.fraud_score),
                color: '#fff'
              }}>
                <span className={styles.scoreValue}>{result.fraud_score}%</span>
              </div>
              <div className={styles.scoreLabel}>
                <span>Risk Score</span>
                <span className={styles.scoreDescription}>
                  {result.fraud_score < 30 ? 'Low Risk' : 
                   result.fraud_score < 70 ? 'Medium Risk' : 'High Risk'}
                </span>
              </div>
            </div>

            <div className={styles.urlInfo}>
              <h3>URL Information</h3>
              <p><strong>Analyzed URL:</strong> {result.url}</p>
              {result.is_trusted_domain && (
                <p className={styles.trusted}>This appears to be a trusted domain</p>
              )}
            </div>

            {result.suspicious_patterns && result.suspicious_patterns.length > 0 && (
              <div className={styles.patternsList}>
                <h3>Suspicious Patterns</h3>
                <ul>
                  {result.suspicious_patterns.map((pattern, index) => (
                    <li key={index} className={styles.patternItem}>
                      {pattern}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {result.feature_contributions && (
              <div className={styles.featuresContainer}>
                <h3>Risk Factors</h3>
                {result.feature_contributions.map((feature, index) => (
                  <div key={index} className={styles.featureItem}>
                    <div className={styles.featureHeader}>
                      <span className={styles.featureName}>{feature.name}</span>
                      <span className={styles.featureValue}>
                        {feature.percentage}%
                      </span>
                    </div>
                    <div className={styles.progressBar}>
                      <div 
                        className={`${styles.progressFill} ${feature.direction === 'decreases' ? styles.decreases : ''}`}
                        style={{ width: `${feature.percentage}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
            
            {debug && (
              <details>
                <summary>Connection Information</summary>
                <pre>{JSON.stringify(debug, null, 2)}</pre>
              </details>
            )}
          </div>
        )}
      </main>

      <footer className={styles.footer}>
        <a
          href="https://github.com/yourusername/fraud-detection-web"
          target="_blank"
          rel="noopener noreferrer"
        >
          Fraud Detection Project
        </a>
      </footer>
    </div>
  );
} 