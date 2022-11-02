<?php

namespace App\Http\Controllers;

use App\Http\Controllers\API\AntrianBPJSController;
use App\Models\Dokter;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use RealRashid\SweetAlert\Facades\Alert;

class DokterController extends Controller
{
    public function index()
    {
        $dokters = Dokter::get();
        return view('simrs.dokter_index', [
            'dokters' => $dokters,
        ]);
    }

    public function create()
    {
        $api = new AntrianBPJSController();
        $dokters = $api->ref_dokter()->response;
        foreach ($dokters as $value) {
            Dokter::updateOrCreate(
                [
                    'kodedokter' => $value->kodedokter,
                ],
                [
                    'namadokter' => $value->namadokter,
                    'status' => 1,
                ]
            );
            $user = User::updateOrCreate([
                'email' => $value->kodedokter . '@gmail.com',
                'username' => $value->kodedokter,
            ], [
                'name' => $value->namadokter,
                'phone' => $value->kodedokter,
                'password' => bcrypt($value->kodedokter),
            ]);
            $user->assignRole('Dokter');
        }
        Alert::success('Success', 'Refresh Data Dokter Berhasil');
        return redirect()->route('dokter.index');
    }

    public function store(Request $request)
    {
        //
    }

    public function show($id)
    {
        //
    }

    public function edit($id)
    {
        //
    }

    public function update(Request $request, $id)
    {
        //
    }

    public function destroy($id)
    {
        //
    }
}
