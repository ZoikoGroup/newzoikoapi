<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Spatie\Permission\Models\Role;

class AuthenticationController extends Controller
{
    /**
     * Handle login and issue token.
     */
   public function login(Request $request)
{
        $request->validate([
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        // Try to authenticate
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json(['success' => false, 'message' => 'Invalid credentials.'], 401);
        }

        $user = Auth::user();

        // Auto-assign role and permissions to super admin (ID 1)
        if ($user->id === 1 && !$user->hasRole('admin')) {
            $user->assignRole('admin');
            $user->givePermissionTo([
                'create users',
                'edit users',
                'delete users',
                'view users',
            ]);
        }

        // Check if user is active
        if (!$user->status) {
            return response()->json(['success' => false, 'message' => 'User has been disabled.'], 403);
        }

        // Generate Sanctum token
        $token = $user->createToken('appToken')->plainTextToken;

        return response()->json([
            'success' => true,
            'token' => $token, // plain token for frontend
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'status' => $user->status,
                'roles' => $user->getRoleNames(),
            ]
        ]);
    }

    /**
     * Logout user and revoke token.
     */
    public function destroy(Request $request)
{
        $user = $request->user();

        if ($user) {
            // Delete only the current token
            $user->currentAccessToken()->delete();

            // If you want to delete all tokens (logout from all devices), use:
            // $user->tokens()->delete();

            return response()->json(['message' => 'Logged out successfully'], 200);
        }

        return response()->json(['message' => 'No authenticated user found'], 401);
    }

    /**
     * Register a new user with role-based control.
     */
    public function register(Request $request)
    {
        $authUser = Auth::user();
        $selected_role = $request->role ?? 'customer';

        // Validate input
        $validator = Validator::make($request->only('name', 'email', 'password'), [
            'name'     => 'required|unique:users,name',
            'email'    => 'required|email|unique:users,email',
            'password' => 'required|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->messages()
            ], 422);
        }

        // Restrict admin creation
        if ($selected_role === 'admin' && (!$authUser || !$authUser->hasRole('admin'))) {
            return response()->json([
                'success' => false,
                'message' => 'Only admins can create admin users.'
            ], 403);
        }

        // Create user
        $user = User::create([
            'name'     => $request->name,
            'email'    => $request->email,
            'password' => Hash::make($request->password),
            'status'   => $request->status ?? 1,
        ]);

        // Assign role
        $user->assignRole($selected_role);

        // Generate Sanctum token
        $token = $user->createToken('appToken')->plainTextToken;

        return response()->json([
            'success' => true,
            'message' => 'User registered successfully.',
            'token'   => $token,
            'user'    => [
                'id'     => $user->id,
                'name'   => $user->name,
                'email'  => $user->email,
                'status' => $user->status,
                'roles'  => $user->getRoleNames(),
            ],
        ], 201);
    }


    /**
     * Get users by role (admin only).
     */
    public function get_all_users(Request $request)
    {
        $authUser = Auth::user();
        $role = $request->role;

        // Check permission
        if (!$authUser || !$authUser->hasRole('admin')) {
            return response()->json([
                'success' => false,
                'message' => 'Access denied. Only admin can view users.'
            ], 403);
        }

        // Filter by role if valid
        if ($role && in_array($role, ['admin', 'customer', 'subscriber'])) {
            $users = User::whereHas('roles', fn($q) => $q->where('name', $role))->get();
        } else {
            $users = User::all();
        }

        // Format response (hide sensitive fields)
        $formattedUsers = $users->map(function ($user) {
            return [
                'id'     => $user->id,
                'name'   => $user->name,
                'email'  => $user->email,
                'status' => $user->status,
                'roles'  => $user->getRoleNames(),
            ];
        });

        return response()->json([
            'success' => true,
            'count'   => $formattedUsers->count(),
            'users'   => $formattedUsers,
        ], 200);
    }


    /**
     * Update user (admin only).
     */
    public function update_user(Request $request, string $id)
    {
        $authUser = Auth::user();
        $user = User::find($id);

        // Check user exists
        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found.'
            ], 404);
        }

        // Only admin can update
        if (!$authUser || !$authUser->hasRole('admin')) {
            return response()->json([
                'success' => false,
                'message' => 'Access denied.'
            ], 403);
        }

        // Build validation rules only for fields that changed
        $rules = [];
        if ($request->filled('name') && $user->name !== $request->name) {
            $rules['name'] = 'required|string|unique:users,name';
        }
        if ($request->filled('email') && $user->email !== $request->email) {
            $rules['email'] = 'required|email|unique:users,email';
        }
        if ($request->filled('password')) {
            $rules['password'] = 'nullable|min:6';
        }
        if ($request->filled('status')) {
            $rules['status'] = 'boolean';
        }
        if ($request->filled('role')) {
            $rules['role'] = 'in:admin,customer,subscriber';
        }

        // Validate only relevant fields
        if (!empty($rules)) {
            $validator = Validator::make($request->only(array_keys($rules)), $rules);
            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'errors'  => $validator->messages()
                ], 422);
            }
        }

        // Update fields
        if ($request->filled('name')) {
            $user->name = $request->name;
        }
        if ($request->filled('email')) {
            $user->email = $request->email;
        }
        if ($request->filled('password')) {
            $user->password = Hash::make($request->password);
        }
        if ($request->filled('status')) {
            $user->status = $request->status;
        }

        // Update role if provided
        if ($request->filled('role')) {
            $user->syncRoles([$request->role]); // replaces old role(s)
        }

        $user->updated_at = now();
        $user->save();

        return response()->json([
            'success' => true,
            'message' => 'User updated successfully.',
            'user'    => [
                'id'     => $user->id,
                'name'   => $user->name,
                'email'  => $user->email,
                'status' => $user->status,
                'roles'  => $user->getRoleNames(),
            ]
        ], 200);
    }


    /**
     * Delete user (admin only, cannot delete super admin).
     */
    public function delete_user(Request $request, string $id)
    {
        $authUser = Auth::user();

        // Ensure only admins can delete
        if (!$authUser || !$authUser->hasRole('admin')) {
            return response()->json([
                'success' => false,
                'message' => 'Access denied.'
            ], 403);
        }

        // Prevent deleting super admin
        if ((int)$id === 1) {
            return response()->json([
                'success' => false,
                'message' => 'Super admin cannot be deleted.'
            ], 403);
        }

        // Prevent admin from deleting themselves
        if ((int)$id === $authUser->id) {
            return response()->json([
                'success' => false,
                'message' => 'You cannot delete your own account.'
            ], 403);
        }

        // Find user
        $user = User::find($id);

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found.'
            ], 404);
        }

        // Perform soft delete (requires `SoftDeletes` trait in User model)
        $user->delete();

        return response()->json([
            'success' => true,
            'message' => 'User deleted successfully.'
        ], 200);
    }


    /**
     * Show a single user (admin only).
     */
    public function show(string $id)
    {
        $authUser = Auth::user();

        // Only admin can view user details
        if (!$authUser || !$authUser->hasRole('admin')) {
            return response()->json([
                'success' => false,
                'message' => 'Access denied.'
            ], 403);
        }

        // Find user
        $user = User::find($id);

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found.'
            ], 404);
        }

        return response()->json([
            'success' => true,
            'user' => [
                'id'     => $user->id,
                'name'   => $user->name,
                'email'  => $user->email,
                'status' => $user->status,
                'roles'  => $user->getRoleNames(), // Spatie role names
                'created_at' => $user->created_at,
                'updated_at' => $user->updated_at,
            ]
        ], 200);
    }

}
