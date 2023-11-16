import { useState } from 'react';

const Todo = ({ todo, onEdit, onDelete }) => {
  const [isEditModalOpen, setEditModalOpen] = useState(false);
  const [editedTitle, setEditedTitle] = useState(todo.title);
  const [editedDescription, setEditedDescription] = useState(todo.description);
  const [isCompleted, setIsCompleted] = useState(todo.completed);

  const handleEdit = () => {
    onEdit(todo?._id, editedTitle, editedDescription, todo.completed);
    setEditModalOpen(false);
  };

  const handleDelete = () => {
    onDelete(todo?._id);
  };

  const handleComplete = () => {
    onEdit(todo?._id, editedTitle, editedDescription, true)
    setIsCompleted(true);
  };

  return (
    <div className={`border p-4 mb-4 ${isCompleted ? 'bg-gray-200' : ''}`}>
      <h2 className={`text-xl font-semibold ${isCompleted ? 'line-through' : ''}`}>
        {todo?.title}
      </h2>
      <p className={`text-gray-600 ${isCompleted ? 'line-through' : ''}`}>
        {todo?.description}
      </p>

      {isEditModalOpen && (
        <div className="fixed inset-0 flex items-center justify-center bg-gray-700 bg-opacity-50">
          <div className="bg-white p-6 w-96">
            <h2 className="text-2xl font-semibold mb-4">Edit Todo</h2>
            <label className="block text-gray-600 text-sm font-medium mb-1">Title</label>
            <input
              type="text"
              value={editedTitle}
              onChange={(e) => setEditedTitle(e.target.value)}
              className="w-full border rounded px-3 py-2 mb-4 focus:outline-none"
            />
            <label className="block text-gray-600 text-sm font-medium mb-1">Description</label>
            <textarea
              value={editedDescription}
              onChange={(e) => setEditedDescription(e.target.value)}
              className="w-full border rounded px-3 py-2 mb-4 focus:outline-none"
            />
            <button
              onClick={handleEdit}
              className="bg-blue-500 text-white rounded px-4 py-2 mr-2 hover:bg-blue-600 focus:outline-none"
            >
              Save
            </button>
            <button
              onClick={() => setEditModalOpen(false)}
              className="bg-gray-500 text-white rounded px-4 py-2 hover:bg-gray-600 focus:outline-none"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="mt-4">
        <button
          onClick={() => setEditModalOpen(true)}
          className="bg-blue-500 text-white rounded px-4 py-2 mr-2 hover:bg-blue-600 focus:outline-none"
        >
          Edit
        </button>
        <button
          onClick={handleDelete}
          className="bg-red-500 text-white rounded px-4 py-2 mr-2 hover:bg-red-600 focus:outline-none"
        >
          Delete
        </button>
        {!todo?.completed && (<button
          onClick={handleComplete}
          className={`bg-green-500 text-white rounded px-4 py-2 hover:bg-green-600 focus:outline-none ${
            isCompleted ? 'bg-gray-500 hover:bg-gray-600' : ''
          }`}
        >
          Mark as Complete
        </button>) }
      </div>
    </div>
  );
};

export default Todo;
