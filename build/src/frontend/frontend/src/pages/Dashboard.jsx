// Import necessary libraries
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import localforage from 'localforage';
import Todo from '../components/Todo';
import axios from 'axios'

// Dashboard component
const Dashboard = () => {
    const history = useNavigate();

    // State for storing todo information
    const [newTodo, setNewTodo] = useState({ title: '', description: '', completed: false });
    const [todos, setTodos] = useState([]);
    const [profile, setProfile] = useState({});
    const [username, setUsername] = useState('Guest');
    const [token, setToken] = useState('')
    const [loading, setLoading] = useState(true);
    const [refresh, setRefresh] = useState(false);
    // Fetch username from local storage or set a default

    const getTodos = async (token) => {
        const url = "http://localhost:8000/todos"
        try {
            const resp = await axios.get(url, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })

            if (resp.status === 200) {
                return resp.data.data.todos || []
            }
            return []
        } catch (err) {
            alert("error occurred")
            console.error(err)
            return []
        }
    }

    const getProfile = async (token) => {
        const url = "http://localhost:8000/user"
        try {
            const resp = await axios.get(url, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
            if (resp.status === 200) {
                setProfile(resp.data.data.user)
                return resp.data.data.user.fullname
            }
            return "Guest"
        } catch (err) {
            alert("error occurred")
            console.error(err)
            return "Guest"
        }
    }

    useEffect(() => {
        ;(async () => {
            if (!refresh) return
            const token = await localforage.getItem("token")
            if (!token) {
                history('/login')
            }
            setToken(token)
            setTodos(await getTodos(token))
            setRefresh(false)
        })();
    }, [refresh]);

    useEffect(() => {
        ; (async () => {
            setLoading(true);
            const token = await localforage.getItem("token")
            if (!token) {
                history('/login')
            }
            setToken(token)
            setTodos(await getTodos(token))
            setUsername(await getProfile(token));
            setLoading(false);
        })();
    }, [])

    const updateInDB = async (id, title, description, completed) => {
        const url = `http://localhost:8000/todo/${id}`
        const body = {
            title, description, completed
        }

        try {
            const resp = await axios.put(url, body, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })

            if (resp.status === 200) {
                alert("Updated!")
            }
        } catch (err) {
            alert("error occurred")
            console.error(err)
        }
    }

    const deleteFromDB = async (id) => {
        const url = `http://localhost:8000/todo/${id}`

        try {
            const resp = await axios.delete(url, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })

            if (resp.status === 200) {
                alert("Deleted!")
            }
        } catch (err) {
            alert("error occurred")
            console.error(err)
        }
    }

    const insertToDB = async (title, description) => {
        const url = "http://localhost:8000/todo"
        const body = {
            title, description
        }

        try {
            const resp = await axios.post(url, body, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })

            if (resp.status === 201) {
                alert("Created!")
            }
        } catch (err) {
            alert("error occurred")
            console.error(err)
        }
    }

    // Handle form input changes
    const handleNewTodoChange = (e) => {
        const { name, value } = e.target;
        setNewTodo((prevTodo) => ({ ...prevTodo, [name]: value }));
    };

    // Handle form submission
    const handleAddTodo = async (e) => {
        e.preventDefault();
        await insertToDB(newTodo.title, newTodo.description)
        // Add new todo to the list
        setRefresh(true);
        setNewTodo({ title: '', description: '', completed: false });
    };

    // Handle logout
    const handleLogout = async () => {
        // Remove authentication information and redirect to login page
        await localforage.removeItem('token');
        await localforage.removeItem('username');
        history('/login');
    };

    return (
        (!loading ? (
            <div className="min-h-screen flex flex-col">
                {/* Navbar */}
                <nav className="bg-blue-500 p-4 text-white flex justify-between items-center">
                    <div className="text-2xl font-semibold">DevTodo</div>
                    <div className="flex items-center">
                        <p className="mr-4">Welcome, <strong>{username}</strong></p>
                        <button
                            className="bg-white text-blue-500 px-4 py-2 rounded"
                            onClick={handleLogout}
                        >
                            Logout
                        </button>
                    </div>
                </nav>

                {/* Main content */}
                <main className="flex-grow p-4">
                    {/* Todo form */}
                    <form onSubmit={handleAddTodo} className="mb-4">
                        <label htmlFor="title" className="block text-gray-600 text-sm font-medium mb-1">
                            Title
                        </label>
                        <input
                            type="text"
                            id="title"
                            name="title"
                            value={newTodo.title}
                            onChange={handleNewTodoChange}
                            className="w-full border rounded px-3 py-2 focus:outline-none"
                            placeholder="Enter title..."
                            required
                        />
                        <label htmlFor="description" className="block text-gray-600 text-sm font-medium mb-1 mt-2">
                            Description
                        </label>
                        <textarea
                            id="description"
                            name="description"
                            value={newTodo.description}
                            onChange={handleNewTodoChange}
                            className="w-full border rounded px-3 py-2 focus:outline-none"
                            placeholder="Enter description..."
                            rows="3"
                            required
                        />
                        <button
                            type="submit"
                            className="bg-blue-500 text-white rounded px-4 py-2 mt-2 hover:bg-blue-600 focus:outline-none"
                        >
                            Add Todo
                        </button>
                    </form>

                    {/* Todo list */}
                    {todos.map((todo) => (
                        <Todo
                            key={todo?._id}
                            todo={todo}
                            onEdit={async (id, title, description, completed) => {
                                // Update the todo with the new title and description
                                setTodos((prevTodos) =>
                                    prevTodos.map((t) =>
                                        t._id === id ? { ...t, title, description, completed } : t
                                    )
                                );
                                await updateInDB(id, title, description, completed)
                            }}
                            onDelete={async (id) => {
                                // Remove the todo with the specified id
                                setTodos((prevTodos) => prevTodos.filter((t) => t._id !== id));
                                await deleteFromDB(id)
                            }}
                        />
                    ))}

                </main>
            </div>
        ) : (<div>Loading...</div>))
    );
};

export default Dashboard;
