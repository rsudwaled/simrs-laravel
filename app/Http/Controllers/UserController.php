<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use RealRashid\SweetAlert\Facades\Alert;
use Spatie\Permission\Models\Role;

class UserController extends Controller
{
    public function index(Request $request)
    {
        $users = User::with(['roles'])
            ->where(function ($query) use ($request) {
                $query->where('name', "like", "%" . $request->search . "%");
            })
            ->paginate(20);
        $roles = Role::pluck('name', 'id')->toArray();
        return view('admin.user_index', compact(['users', 'request', 'roles']))->with(['i' => 0]);
    }
    public function edit(User $user)
    {
        // $user = User::with('roles')->firstWhere('username', $user->username);
        $roles = Role::pluck('name', 'id');
        return view('admin.user_edit', compact(['user', 'roles']));
    }
    public function store(Request $request)
    {
        $request->validate([
            'username' => 'required|alpha_dash|unique:users,username,' . $request->id,
            'name' => 'required',
        ]);
        if (!empty($request['password'])) {
            $request['password'] = Hash::make($request['password']);
        } else {
            $request = Arr::except($request, array('password'));
        }
        $user = User::updateOrCreate(['id' => $request->id], $request->except(['_token', 'id', 'role']));
        DB::table('model_has_roles')->where('model_id', $request->id)->delete();
        $user->assignRole($request->role);
        Alert::success('Success', 'Data Telah Disimpan');
        return redirect()->route('admin.user.index');
    }
    public function destroy(User $user)
    {
        $user->delete();
        Alert::success('Success', 'Data Telah Dihapus');
        return redirect()->route('admin.user.index');
    }
    public function profile()
    {
        $user = Auth::user();
        $roles = Role::pluck('name', 'name')->all();
        $userRole = $user->roles->pluck('name', 'name')->all();
        // $genders = Gender::pluck('name', 'name')->all();
        // $agamas = Agama::pluck('name', 'name')->all();
        // $perkawinans = Perkawinan::pluck('name', 'name')->all();
        // $provinces = Province::pluck('name', 'id');
        // $cities = City::where('province_code', $user->province_id)->pluck('name', 'id')->all();
        // $districts = District::where('city_code', $user->city_id)->pluck('name', 'id')->all();
        // $villages = Village::where('district_code', $user->district_id)->pluck('name', 'id')->all();
        return view('admin.user_profile', compact(
            'user',
            'roles',
            'userRole',
        ));
    }
    public function profile_update(Request $request)
    {
        $user = Auth::user();
        $request->validate([
            'name' => 'required',
            'email' => 'unique:users,email,' . $user->id,
            'username' => 'required|alpha_dash|unique:users,username,' . $user->id,
        ]);
        $user->update($request->all());
        Alert::success('Success', 'Data Telah Disimpan');
        return redirect()->route('profil');
    }
}
