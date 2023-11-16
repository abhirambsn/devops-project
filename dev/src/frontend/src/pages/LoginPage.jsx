// Import necessary libraries
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import localforage from 'localforage'
import axios from 'axios'

// Login component
const LoginPage = () => {
  const history = useNavigate()

  const authenticateUser = async (username, password) => {
    const url = "http://localhost:8000/login"
    const body = {username, password}

    try {
      const resp = await axios.post(url, body)
      if (resp.status === 200) {
        alert("Logged In!")
        await localforage.setItem("token", resp.data.data.token)
        return true
      }
    } catch (err) {
      alert("error occurred")
      console.error(err)
      return false
    }
  }

  useEffect(() => {
    localforage.getItem("token").then(authTok => {
      if (authTok) {
        history('/')
      }
    });
  }, [])

  const [credentials, setCredentials] = useState({
    username: '',
    password: '',
  });

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setCredentials({ ...credentials, [name]: value });
  };

  const handleLogin = (e) => {
    e.preventDefault();
    // Add authentication logic here
    const auth = authenticateUser(credentials.username, credentials.password)
    if (auth) history('/')
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded shadow-md w-96">
        <h1 className="text-2xl font-semibold mb-4 text-center">DevTodo Login</h1>
        <form onSubmit={handleLogin}>
          <div className="mb-4">
            <label htmlFor="email" className="block text-gray-600 text-sm font-medium mb-1">
              Username
            </label>
            <input
              type="text"
              id="username"
              name="username"
              value={credentials.username}
              onChange={handleInputChange}
              className="w-full border rounded px-3 py-2 focus:outline-none focus:border-blue-500"
              required
            />
          </div>
          <div className="mb-4">
            <label htmlFor="password" className="block text-gray-600 text-sm font-medium mb-1">
              Password
            </label>
            <input
              type="password"
              id="password"
              name="password"
              value={credentials.password}
              onChange={handleInputChange}
              className="w-full border rounded px-3 py-2 focus:outline-none focus:border-blue-500"
              required
            />
          </div>
          <div className="mb-4 text-center">
            <Link to="/register" className="text-blue-500 italic hover:underline">
              Don't have an account? Register here.
            </Link>
          </div>
          <button
            type="submit"
            className="bg-blue-500 text-white rounded px-4 py-2 w-full hover:bg-blue-600 focus:outline-none"
          >
            Login
          </button>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;
