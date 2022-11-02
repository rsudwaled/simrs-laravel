<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Illuminate\Support\Str;

class RoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $roles = [
            'Admin',
            'Pendaftaran',
            'Poliklinik',
            'Dokter',
            'Kasir',
            'BPJS',
            'Farmasi',
            'Rekam Medis',
            'Pelayanan Medis',
        ];
        foreach ($roles as $item) {
            $permission = Permission::create(['name' => Str::slug($item)]);
            $role = Role::create(['name' => $item]);
            $role->syncPermissions($permission);
        }

        $role = Role::create(['name' => 'Admin Super']);
        $permissions = Permission::pluck('id', 'id')->all();
        $role->syncPermissions($permissions);
    }
}
