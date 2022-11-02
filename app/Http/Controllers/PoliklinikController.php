<?php

namespace App\Http\Controllers;

use App\Http\Controllers\API\AntrianBPJSController;
use App\Models\Dokter;
use App\Models\JadwalPoli;
use App\Models\Poliklinik;
use App\Models\PoliklinikDB;
use App\Models\UnitDB;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use RealRashid\SweetAlert\Facades\Alert;

class PoliklinikController extends Controller
{
    public function index()
    {
        $polis = Poliklinik::get();
        return view('simrs.poli_index', [
            'polis' => $polis
        ]);
    }
    public function create()
    {
        $api = new AntrianBPJSController();
        $poli = $api->ref_poli()->response;
        $poliDB = UnitDB::where('KDPOLI', '!=', null)->get(['kode_unit', 'nama_unit', 'KDPOLI',]);
        foreach ($poli as $value) {
            if ($value->kdpoli == $value->kdsubspesialis) {
                $subpesialis = 0;
            } else {
                $subpesialis = 1;
            }
            Poliklinik::updateOrCreate(
                [
                    'kodepoli' => $value->kdpoli,
                    'kodesubspesialis' => $value->kdsubspesialis,
                ],
                [
                    'namapoli' => $value->nmpoli,
                    'namasubspesialis' => $value->nmsubspesialis,
                    'subspesialis' => $subpesialis,
                    'lokasi' => 1,
                    'loket' => 1,
                    'status' => 0,
                ]
            );
        }
        // update aktif
        $poli_jkn = Poliklinik::get();
        foreach ($poli_jkn as $poli) {
            foreach ($poliDB as $unit) {
                if ($poli->kodesubspesialis ==  $unit->KDPOLI) {
                    if (isset($unit->lokasi)) {
                        $lokasi = $unit->lokasi->lokasi;
                        $loket = $unit->lokasi->loket;
                    } else {
                        $lokasi = 0;
                        $loket = 0;
                    }
                    $poli->update([
                        'status' => 1,
                        'lokasi' => $lokasi,
                        'loket' => $loket,
                    ]);
                    $user = User::updateOrCreate([
                        'email' => $poli->kodesubspesialis . '@gmail.com',
                        'username' => $poli->kodesubspesialis,
                    ], [
                        'name' => 'ADMIN POLI ' . $poli->namasubspesialis,
                        'phone' => '089529909036',
                        'password' => bcrypt('adminpoli'),
                    ]);
                    $user->assignRole('Poliklinik');
                }
            }
        }
        Alert::success('Success', 'Refresh Poliklinik Berhasil');
        return redirect()->route('poli.index');
    }
    public function edit($id)
    {
        $poli = Poliklinik::find($id);
        if ($poli->status == '0') {
            $status = 1;
            $keterangan = 'Aktifkan';
        } else {
            $status = 0;
            $keterangan = 'Non-Aktifkan';
        }
        $poli->update([
            'status' => $status,
        ]);
        Alert::success('Success', 'Poliklinik ' . $poli->namasubspesialis . ' Telah Di ' . $keterangan);
        return redirect()->route('poli.index');
    }
    public function show($id)
    {
        $poli = Poliklinik::find($id);
        return response()->json($poli);
    }
    public function store(Request $request)
    {
        $poli = Poliklinik::find($request->idpoli);
        if ($request->status == "true") {
            $request['status'] = 1;
        } else {
            $request['status'] = 0;
        }
        $poli->update([
            'lokasi' => $request->lokasi,
            'loket' => $request->lantaipendaftaran,
            'status' => $request->status,
        ]);
        Alert::success('Success', 'Poliklinik ' . $poli->namasubspesialis . ' telah diperbaharui');
        return redirect()->route('poli.index');
    }
}
