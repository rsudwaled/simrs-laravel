<?php

namespace App\Http\Controllers;

use App\Http\Controllers\API\AntrianBPJSController;
use App\Models\Dokter;
use App\Models\JadwalDokter;
use App\Models\Poliklinik;
use App\Models\PoliklinikDB;
use Illuminate\Http\Request;
use RealRashid\SweetAlert\Facades\Alert;


class JadwalDokterController extends Controller
{
    public function index()
    {
        $poli = PoliklinikDB::where('status', 1)->get();
        $dokters = Dokter::get();
        $jadwals = JadwalDokter::get();
        return view('simrs.jadwaldokter_index', [
            'poli' => $poli,
            'jadwals' => $jadwals,
            'dokters' => $dokters,
        ]);
    }
    public function store(Request $request)
    {
        if ($request->method == 'GET') {
            $api = new AntrianBPJSController();
            $polis = PoliklinikDB::where('status', 1)->get('kodesubspesialis');
            $jumlah_jadwal = 0;
            foreach ($polis as $value) {
                $request['kodepoli'] = $value->kodesubspesialis;
                $jadwals = $api->ref_jadwal_dokter($request);
                if (isset($jadwals->response)) {
                    foreach ($jadwals->response as  $jadwal) {
                        JadwalDokter::updateOrCreate(
                            [
                                'kodesubspesialis' => $jadwal->kodesubspesialis,
                                'kodedokter' => $jadwal->kodedokter,
                                'hari' => $jadwal->hari,
                                'kodepoli' => $jadwal->kodepoli,
                                'namapoli' => $jadwal->namapoli,
                                'namasubspesialis' => $jadwal->namasubspesialis,
                                'namadokter' => str_replace(',', '.', $jadwal->namadokter),
                                'namahari' => $jadwal->namahari,
                                'jadwal' => $jadwal->jadwal,
                                'libur' => $jadwal->libur,
                                'kapasitaspasien' => $jadwal->kapasitaspasien,
                            ]
                        );
                    }
                    $jumlah_jadwal++;
                }
            }
            Alert::success('Success', 'Jadwal Telah Ditambahkan berjumlah ' . $jumlah_jadwal . ' Poliklinik');
            return redirect()->route('jadwaldokter.index');
        }
        if ($request->method == "UPDATE") {
            $jadwal = JadwalDokter::find($request->idjadwal);
            // dd($jadwal);
            $poli = PoliklinikDB::firstWhere('kodesubspesialis', $request->kodesubspesialis);
            $dokter = Dokter::firstWhere('kodedokter', $request->kodedokter);
            $hari = ['MINGGU', 'SENIN', 'SELASA', 'RABU', 'KAMIS', 'JUMAT', 'SABTU'];
            if ($request->libur == "true") {
                $libur = 1;
            } else {
                $libur = 0;
            }
            $jadwal->update([
                'kodesubspesialis' => $poli->kodesubspesialis,
                'kodedokter' => $dokter->kodedokter,
                'hari' => $request->hari,
                'kodepoli' => $poli->kodepoli,
                'namapoli' => $poli->namapoli,
                'namasubspesialis' => $poli->namasubspesialis,
                'namadokter' =>  str_replace(',', '.', $dokter->namadokter),
                'namahari' => $hari[$request->hari],
                'jadwal' => $request->jadwal,
                'libur' => $libur,
                'kapasitaspasien' => $request->kapasitaspasien,
            ]);
            Alert::success('Success', 'Jadwal Telah Diperbarui');
            return redirect()->route('jadwaldokter.index');
        }
        if ($request->method == "DELETE") {
            $jadwal = JadwalDokter::find($request->idjadwal);
            // dd($jadwal);
            $jadwal->delete();
            Alert::success('Success', 'Jadwal Telah Dihapus');
            return redirect()->route('jadwaldokter.index');
        }
    }
    public function edit($id)
    {
        $jadwal = JadwalDokter::find($id);
        return response()->json($jadwal);
    }
}
