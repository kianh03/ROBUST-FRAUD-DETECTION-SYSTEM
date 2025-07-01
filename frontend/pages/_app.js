import '../styles/globals.css'
import '../styles/auth.css'
import { AuthProvider } from '../firebase/AuthContext'

function MyApp({ Component, pageProps }) {
  return (
    <AuthProvider>
      <Component {...pageProps} />
    </AuthProvider>
  )
}

export default MyApp 