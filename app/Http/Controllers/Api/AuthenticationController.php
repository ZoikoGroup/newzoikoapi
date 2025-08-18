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
    public function store()
    {
        if (Auth::attempt(['email' => request('email'), 'password' => request('password')])) {
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

            if ($user->status) {
                $token = $user->createToken('appToken')->plainTextToken;
                // $token = $user->createToken('appToken')->accessToken;

                return response()->json([
                    'success' => true,
                    'token' => ['token' => $token],
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'status' => $user->status,
                        'roles' => $user->getRoleNames(),
                    ]
                ]);
            }

            return response()->json(['success' => false, 'message' => 'User has been disabled.'], 403);
        }

        return response()->json(['success' => false, 'message' => 'Invalid credentials.'], 401);
    }

    /**
     * Logout user and revoke token.
     */
    public function destroy(Request $request)
    {
        if (Auth::user()) {
            $request->user()->token()->revoke();
            return response()->json(['message' => 'Logged out successfully'], 200);
        }
    }

    /**
     * Register a new user with role-based control.
     */
    public function register(Request $request)
    {
        $authUser = Auth::user();
        $selected_role = $request->role ?? 'customer';

        $validator = Validator::make($request->only('name', 'email', 'password'), [
            'name' => 'required|unique:users',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->messages()], 422);
        }

        if ($selected_role === 'admin' && (!$authUser || !$authUser->hasRole('admin'))) {
            return response()->json([
                'success' => false,
                'message' => 'Only admins can create admin users.'
            ], 403);
        }

        $user = User::create([
            'name'       => $request->name,
            'email'      => $request->email,
            'password'   => Hash::make($request->password),
            'status'     => $request->status ?? 1,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $user->assignRole($selected_role);

        return response()->json([
            'success' => true,
            'message' => 'User registered successfully.',
            'user'    => $user,
        ], 201);
    }

    /**
     * Get users by role (admin only).
     */
    public function get_all_users(Request $request)
    {
        $user = Auth::user();
        $role = $request->role;

        if (!$user || !$user->hasRole('admin')) {
            return response()->json(['message' => 'Access denied. Only admin can view users.'], 403);
        }

        if (in_array($role, ['admin', 'customer', 'subscriber'])) {
            $users = User::whereHas('roles', fn($q) => $q->where('name', $role))->get();
        } else {
            $users = User::all();
        }

        return response()->json(['success' => true, 'users' => $users], 200);
    }

    /**
     * Update user (admin only).
     */
    public function update_user(Request $request, string $id)
    {
        $authUser = Auth::user();
        $user = User::find($id);

        if (!$user) {
            return response()->json(['success' => false, 'message' => 'User not found.'], 404);
        }

        if (!$authUser || !$authUser->hasRole('admin')) {
            return response()->json(['message' => 'Access denied.'], 403);
        }

        $rules = [];

        if ($user->name !== $request->name) {
            $rules['name'] = 'required|unique:users';
        }

        if ($user->email !== $request->email) {
            $rules['email'] = 'required|email|unique:users';
        }

        if (!empty($rules)) {
            $validator = Validator::make($request->only('name', 'email'), $rules);
            if ($validator->fails()) {
                return response()->json(['success' => false, 'error' => $validator->messages()], 422);
            }
        }

        $user->name = $request->name;
        $user->email = $request->email;

        if (!empty($request->password)) {
            $user->password = Hash::make($request->password);
        }

        $user->updated_at = now();

        $user->save();

        return response()->json(['success' => true, 'message' => 'User updated.', 'user' => $user]);
    }

    /**
     * Delete user (admin only, cannot delete super admin).
     */
    public function delete_user(Request $request, string $id)
    {
        $authUser = Auth::user();

        if (!$authUser || !$authUser->hasRole('admin')) {
            return response()->json(['message' => 'Access denied.'], 403);
        }

        if ($id == 1) {
            return response()->json(['success' => false, 'message' => 'Super admin cannot be deleted.'], 403);
        }

        $user = User::find($id);

        if (!$user) {
            return response()->json(['success' => false, 'message' => 'User not found.'], 404);
        }

        $user->delete();

        return response()->json(['success' => true, 'message' => 'User deleted.']);
    }

    /**
     * Show a single user (admin only).
     */
    public function show(string $id)
    {
        $authUser = Auth::user();

        if (!$authUser || !$authUser->hasRole('admin')) {
            return response()->json(['message' => 'Access denied.'], 403);
        }

        $user = User::find($id);

        if (!$user) {
            return response()->json(['success' => false, 'message' => 'User not found.'], 404);
        }

        return response()->json([
            'user' => $user,
            'roles' => $user->getRoleNames()
        ]);
    }
}
