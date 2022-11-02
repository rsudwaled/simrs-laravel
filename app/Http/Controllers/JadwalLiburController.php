<?php

namespace App\Http\Controllers;

use App\Http\Controllers\API\WhatsappController;
use App\Models\Antrian;
use App\Models\AntrianDB;
use App\Models\JadwalLiburPoliDB;
use App\Models\UnitDB;
use Carbon\Carbon;
use Illuminate\Http\Request;
use RealRashid\SweetAlert\Facades\Alert;

class JadwalLiburController extends Controller
{
    public function index(Request $request)
    {
        $jadwals = JadwalLiburPoliDB::with(['unit', 'unit.antrians'])
            ->latest()
            ->paginate();
        $polikliniks = UnitDB::where('kelas_unit', 1)
            ->where('ACT', 1)
            ->pluck('nama_unit', 'kode_unit')->toArray();
        return view('simrs.jadwallibur_index', [
            'request' => $request,
            'jadwals' => $jadwals,
            'polikliniks' => $polikliniks
        ]);
    }
    public function store(Request $request)
    {
        $request->validate([
            'tanggal' => 'required',
            'kode_poli' => 'required',
        ]);
        $tanggal = explode('-', $request->tanggal);
        $tanggal_awal = Carbon::parse($tanggal[0])->format('Y-m-d');
        $tanggal_akhir = Carbon::parse($tanggal[1])->format('Y-m-d');
        $poli = UnitDB::firstWhere('kode_unit', $request->kode_poli);
        $jadwal = JadwalLiburPoliDB::updateOrCreate(
            [
                'id' => $request->id,
            ],
            [
                'tanggal_awal' => $tanggal_awal,
                'tanggal_akhir' => $tanggal_akhir,
                'kode_poli' => $request->kode_poli,
                'kodepoli' => $poli->KDPOLI,
                'keterangan' => $request->keterangan,
                'status' => 1,
            ]
        );
        Alert::success('Berhasil', 'Data berhasil disimpan');
        return redirect()->route('jadwallibur.index');
    }
    public function show($id, Request $request)
    {
        $jadwal = JadwalLiburPoliDB::findOrFail($id);
        if ($jadwal->kode_poli == 0) {
            $antrians = Antrian::whereBetween('tanggalperiksa', [$jadwal->tanggal_awal, $jadwal->tanggal_akhir])->get();
        } else {
            $antrians = $jadwal->unit->antrians->whereBetween('tanggalperiksa', [$jadwal->tanggal_awal, $jadwal->tanggal_akhir]);
        }

        $api = new WhatsappController;
        foreach ($antrians as $antrian) {
            $antrian->update([
                'taskid' => 99
            ]);
            $request['message'] = "Mohon maaf nomor antrian anda dengan kode *" . $antrian->kodebooking . "* pada tanggal *" . $antrian->tanggalperiksa . "* untuk ke *POLI " . $antrian->namapoli . "* dibatalkan karena pada hari itu poli tersebut diliburkan dengan keterangan *" . $jadwal->keterangan . "*";
            $request['number'] = $antrian->nohp;
            $api->send_message($request);
        }
        $jadwal->update([
            'status' => 2,
        ]);
        Alert::success('Success', 'Libur telah dikonfirmasi kepada semua antrian pasien');
        return redirect()->route('jadwallibur.index');
    }
    public function edit($id)
    {
        $jadwal = JadwalLiburPoliDB::findOrFail($id);
        $polikliniks = UnitDB::where('kelas_unit', 1)
            ->where('ACT', 1)
            ->pluck('nama_unit', 'kode_unit')->toArray();
        return view('pelayananmedis::jadwal_libur_poli_edit', [
            'jadwal' => $jadwal,
            'polikliniks' => $polikliniks
        ]);
    }
    public function destroy($id)
    {
        $jadwal = JadwalLiburPoliDB::findOrFail($id);
        $jadwal->delete();
        Alert::success('Success', 'Libur telah dihapus');
        return redirect()->route('jadwallibur.index');
    }
}
