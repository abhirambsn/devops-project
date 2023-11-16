// Import necessary libraries
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import localforage from 'localforage';
import axios from 'axios'

// Register component
const RegisterPage = () => {
    const history = useNavigate()

    useEffect(() => {
        localforage.getItem("token").then(authTok => {
            if (authTok) {
                history('/')
            }
        });
    }, [history])

    const [registrationInfo, setRegistrationInfo] = useState({
        username: '',
        password: '',
        confirmPassword: '',
        fullName: '',
    });

    const [validationMessage, setValidationMessage] = useState('');

    const registerUser = async (username, password, fullname) => {
        const url = "http://localhost:8000/user"
        const body = { username, password, fullname }

        try {
            const resp = await axios.post(url, body)
            if (resp.status === 201) {
                alert("Registered!!")
                return true;
            }
        } catch (err) {
            alert("error occured")
            console.error(err)
            return false;
        }
    }
    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setRegistrationInfo({ ...registrationInfo, [name]: value });
    };

    const handleRegister = async (e) => {
        e.preventDefault();
        if (registrationInfo.password !== registrationInfo.confirmPassword) {
            setValidationMessage('Password and Confirm Password do not match.');
            return;
        }
        const reg = await registerUser(registrationInfo.username, registrationInfo.password, registrationInfo.fullName)
        if (reg) {
            history('/login');
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-100">
            <div className="bg-white p-8 rounded shadow-md w-96">
                <h1 className="text-2xl font-semibold mb-4 text-center">DevTodo Register</h1>
                <form onSubmit={handleRegister}>
                    <div className="mb-4">
                        <label htmlFor="fullName" className="block text-gray-600 text-sm font-medium mb-1">
                            Full Name
                        </label>
                        <input
                            type="text"
                            id="fullName"
                            name="fullName"
                            value={registrationInfo.fullName}
                            onChange={handleInputChange}
                            className="w-full border rounded px-3 py-2 focus:outline-none focus:border-blue-500"
                            required
                        />
                    </div>
                    <div className="mb-4">
                        <label htmlFor="username" className="block text-gray-600 text-sm font-medium mb-1">
                            Username
                        </label>
                        <input
                            type="text"
                            id="username"
                            name="username"
                            value={registrationInfo.username}
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
                            value={registrationInfo.password}
                            onChange={handleInputChange}
                            className="w-full border rounded px-3 py-2 focus:outline-none focus:border-blue-500"
                            required
                        />
                    </div>
                    <div className="mb-4">
                        <label htmlFor="confirmPassword" className="block text-gray-600 text-sm font-medium mb-1">
                            Confirm Password
                        </label>
                        <input
                            type="password"
                            id="confirmPassword"
                            name="confirmPassword"
                            value={registrationInfo.confirmPassword}
                            onChange={handleInputChange}
                            className="w-full border rounded px-3 py-2 focus:outline-none focus:border-blue-500"
                            required
                        />
                    </div>
                    {validationMessage && (
                        <p className="text-red-500 text-sm mb-4">{validationMessage}</p>
                    )}
                    <div className="mb-4 text-center">
                        <Link to="/login" className="text-blue-500 italic hover:underline">
                            Already have an account? Login here.
                        </Link>
                    </div>
                    <button
                        type="submit"
                        className="bg-blue-500 text-white rounded px-4 py-2 w-full hover:bg-blue-600 focus:outline-none"
                    >
                        Register
                    </button>
                </form>
            </div>
        </div>
    );
};

export default RegisterPage;
