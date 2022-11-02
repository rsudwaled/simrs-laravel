<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Spatie\Permission\Models\Permission;
use Illuminate\Support\Str;
use RealRashid\SweetAlert\Facades\Alert;

class PermissionController extends Controller
{
    public function store(Request $request)
    {
        $request->validate([
            'name' => 'required|alpha_dash|unique:permissions,name,' . $request->id,
        ]);
        Permission::updateOrCreate(['id' => $request->id], ['name' => Str::slug($request->name)]);
        Alert::success('Success', 'Data Telah Disimpan');
        return redirect()->route('admin.role.index');
    }
    public function edit(Permission $permission)
    {
        // $permission = Permission::firstWhere('name', $name);
        return view('admin.permission_edit', compact(['permission']));
    }
    public function destroy(Permission $permission)
    {
        // $permission = Permission::find($id);
        if ($permission->roles()->exists()) {
            Alert::error('Gagal Menghapus', 'Permission masih memiliki permission');
        } else {
            $permission->delete();
            Alert::success('Success', 'Permission Telah Dihapus');
        }
        return redirect()->route('admin.role.index');
    }
}
