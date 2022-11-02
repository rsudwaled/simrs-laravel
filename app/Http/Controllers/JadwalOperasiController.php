<?php

namespace App\Http\Controllers;

use App\Models\Dokter;
use App\Models\JadwalOperasi;
use App\Models\Poliklinik;
use Illuminate\Http\Request;
use RealRashid\SweetAlert\Facades\Alert;

class JadwalOperasiController extends Controller
{
    public function index()
    {
        $dokters = Dokter::get();
        $poli = Poliklinik::get();
        $jadwals = JadwalOperasi::get();
        return view('simrs.jadwaloperasi_index', [
            'dokters' => $dokters,
            'poli' => $poli,
            'jadwals' => $jadwals
        ]);
    }

    public function create()
    {
        //
    }

    public function store(Request $request)
    {
        if ($request->method == 'STORE') {
            $request['kodebooking'] = strtoupper(uniqid());
            $request['kodetindakan'] = $request->jenistindakan;
            $poli = Poliklinik::where('kodesubspesialis',  $request->kodepoli)->first();
            $request['namapoli'] = $poli->namasubspesialis;
            $dokter = Dokter::where('kodedokter', $request->kodedokter)->first();
            $request['namadokter'] = $dokter->namadokter;
            $request->validate([
                'kodebooking' => 'required',
                'tanggaloperasi' => 'required',
                'kodetindakan' => 'required',
                'jenistindakan' => 'required',
                'kodepoli' => 'required',
                'namapoli' => 'required',
                'kodedokter' => 'required',
                'namadokter' => 'required',
                'nopeserta' => 'required',
                'nik' => 'required',
                'norm' => 'required',
                'namapeserta' => 'required',
            ]);
            JadwalOperasi::create([
                'kodebooking' => $request->kodebooking,
                'tanggaloperasi' => $request->tanggaloperasi,
                'kodetindakan' => $request->kodetindakan,
                'jenistindakan' => $request->jenistindakan,
                'kodepoli' => $request->kodepoli,
                'namapoli' => $request->namapoli,
                'kodedokter' => $request->kodedokter,
                'namadokter' => $request->namadokter,
                'terlaksana' => 0,
                'nopeserta' => $request->nopeserta,
                'nik' => $request->nik,
                'norm' => $request->norm,
                'namapeserta' => $request->namapeserta,
            ]);
            Alert::success('Success', 'Jadwal Telah Ditambahkan');
            return redirect()->route('jadwaloperasi.index');
        }
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
