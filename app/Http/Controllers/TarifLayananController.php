<?php

namespace App\Http\Controllers;

use App\Models\TarifLayanan;
use App\Http\Requests\StoreTarifLayananRequest;
use App\Http\Requests\UpdateTarifLayananRequest;
use App\Models\TarifLayananDB;
use App\Models\TarifLayananDetail;
use App\Models\TarifLayananDetailDB;
use RealRashid\SweetAlert\Facades\Alert;

class TarifLayananController extends Controller
{
    public function index()
    {
        $tariflayanans = TarifLayananDB::with(['tarifdeails'])->paginate();
        // dd($tariflayanans);
        // $tarifdetails = TarifLayananDetailDB::get();
        return view('simrs.tarif_layanan_index', [
            'tariflayanans' => $tariflayanans,
        ]);
    }
    public function create()
    {
        $tariflayanans = TarifLayananDB::where('USER_INPUT_ID', 1)->get();
        foreach ($tariflayanans as $tarif) {
            TarifLayanan::updateOrCreate(
                [
                    'kodetarif' => $tarif->KODE_TARIF_HEADER,
                ],
                [
                    'nosk' => $tarif->NO_SK,
                    'namatarif' => $tarif->NAMA_TARIF,
                    'tarifkelompokid' => $tarif->KELOMPOK_TARIF_ID,
                    'tarifvclaimid' => $tarif->ID_VCLAIM,
                    'keterangan' => $tarif->keterangan,
                    'status' => $tarif->USER_INPUT_ID,
                    'userid' => 1,
                ]
            );
            $tarifdetails = TarifLayananDetailDB::where('KODE_TARIF_HEADER', $tarif->KODE_TARIF_HEADER)->get();
            foreach ($tarifdetails as $detail) {
                TarifLayananDetail::updateOrCreate([
                    'kodetarifdetail' => $detail->KODE_TARIF_DETAIL,
                    'kodetarif' => $detail->KODE_TARIF_HEADER,
                    'kelas' => $detail->KELAS_TARIF,
                    'totaltarif' => $detail->TOTAL_TARIF_NEW,
                    'userid' => 1,
                ]);
            }
        }
        Alert::success('Berhasil', 'Data Tarif Kelompok Layanan Berhasil Diimport');
        return redirect()->route('tarif_layanan.index');
    }

    public function store(StoreTarifLayananRequest $request)
    {
        //
    }

    public function show(TarifLayanan $tarifLayanan)
    {
        //
    }

    public function edit(TarifLayanan $tarifLayanan)
    {
        //
    }

    public function update(UpdateTarifLayananRequest $request, TarifLayanan $tarifLayanan)
    {
        //
    }

    public function destroy(TarifLayanan $tarifLayanan)
    {
        //
    }
}
