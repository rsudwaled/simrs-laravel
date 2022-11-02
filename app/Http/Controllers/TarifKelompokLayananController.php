<?php

namespace App\Http\Controllers;

use App\Models\TarifKelompokLayanan;
use App\Http\Requests\StoreTarifKelompokLayananRequest;
use App\Http\Requests\UpdateTarifKelompokLayananRequest;
use App\Models\TarifKelompokLayananDB;
use RealRashid\SweetAlert\Facades\Alert;

class TarifKelompokLayananController extends Controller
{
    public function index()
    {
        $tarifkelompoks = TarifKelompokLayanan::get();
        return view('simrs.tarif_layanan_kelompok_index', [
            'tarifkelompoks' => $tarifkelompoks,
        ]);
    }

    public function create()
    {
        $tarifkelompoks = TarifKelompokLayananDB::get();
        foreach ($tarifkelompoks as $tarif) {
            TarifKelompokLayanan::updateOrCreate([
                'namatarifkelompok' => $tarif->kelompok_tarif_name,
                'prefix' => $tarif->kelompok_tarif_prefix,
                'grouptarif' => $tarif->group_tarif,
                'groupvclaim' => $tarif->group_vclaim,
                'keterangan' =>  $tarif->ket,
            ]);
        }
        Alert::success('Berhasil', 'Data Tarif Kelompok Layanan Berhasil Diimport');
        return redirect()->route('tarif_kelompok_layanan.index');
    }

    public function store(StoreTarifKelompokLayananRequest $request)
    {
        //
    }

    public function show(TarifKelompokLayanan $tarifKelompokLayanan)
    {
        //
    }

    public function edit(TarifKelompokLayanan $tarifKelompokLayanan)
    {
        //
    }

    public function update(UpdateTarifKelompokLayananRequest $request, TarifKelompokLayanan $tarifKelompokLayanan)
    {
        //
    }

    public function destroy(TarifKelompokLayanan $tarifKelompokLayanan)
    {
        //
    }
}
