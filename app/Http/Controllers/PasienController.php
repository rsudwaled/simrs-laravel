<?php

namespace App\Http\Controllers;

use App\Models\Agama;
use App\Models\PasienDB;
use App\Models\Pekerjaan;
use App\Models\Pendidikan;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use RealRashid\SweetAlert\Facades\Alert;

class PasienController extends Controller
{
    public function index(Request $request)
    {
        $pasiens = PasienDB::latest()
            ->where('no_rm', 'LIKE', "%{$request->search}%")
            ->orWhere('nama_px', 'LIKE', "%{$request->search}%")
            ->orWhere('nik_bpjs', 'LIKE', "%{$request->search}%")
            ->simplePaginate(20);
        $total_pasien = PasienDB::count();
        $pasien_jkn = PasienDB::where('no_Bpjs', '!=', '')->count();
        $pasien_nik = PasienDB::where('nik_bpjs', '!=', '')->count();
        $pasien_laki = PasienDB::where('jenis_kelamin', 'L')->count();
        $pasien_perempuan = PasienDB::where('jenis_kelamin', 'P')->count();
        return view('simrs.pasien_index', compact([
            'pasiens',
            'request',
            'total_pasien',
            'pasien_jkn',
            'pasien_nik',
            'pasien_laki',
            'pasien_perempuan',
        ]));
    }
    public function store(Request $request)
    {
        $request->validate([
            'nik' => 'required|unique:users,nik,' . $request->user_id,
            'nama' => 'required',
            'tempat_lahir' => 'required',
            'tanggal_lahir' => 'required',
            'no_rm' => 'required',
        ]);
        $request['username'] = $request->nik;
        $request['tanggal_lahir'] = date('Y-m-d', strtotime($request->tanggal_lahir));
        // $user = User::updateOrCreate(['id' => $request->user_id], $request->except(['_token', 'role']));
        // $user->assignRole('Pasien');
        $pasien = PasienDB::updateOrCreate(['no_rm' => $request->no_rm], [
            'nik_bpjs' => $request->nik,
            'nama_px' => $request->nama,
            'tempat_lahir' => $request->tempat_lahir,
            'tgl_lahir' => $request->tanggal_lahir,
        ]);
        Alert::success('Success', 'Data Pasien Telah Disimpan');
        return redirect()->route('pasien.index');
    }
    public function update(Request $request, PasienDB $pasien)
    {
        $request->validate([
            'nik' => 'required',
            'nokartu' => 'required',
            'nama' => 'required',
            'norm' => 'required',
        ]);
        $pasien->update([
            'nik_bpjs' => $request->nik,
            'no_Bpjs' => $request->nokartu,
            'nama_px' => $request->nama,
        ]);
        Alert::success('Success', 'Data Pasien Telah Disimpan');
        return redirect()->route('pasien.index');
    }
    public function edit($no_rm)
    {
        $pasien = PasienDB::firstWhere('no_rm', $no_rm);
        return view('simrs.pasien_edit', compact('pasien'));
    }
    public function caripasien(Request $request)
    {
        $pasien = PasienDB::firstWhere('no_rm', $request->norm);
        return response()->json($pasien);
    }
    public function destroy($no_rm)
    {
        $pasien = PasienDB::firstWhere('no_rm', $no_rm);
        $pasien->delete();
        Alert::success('Success', 'Data Pasien Telah Dihapus');
        return redirect()->route('pasien.index');
    }
    public function pasien_daerah(Request $request)
    {
        $pasiens_kecamatan = PasienDB::select('kode_kecamatan', DB::raw('count(*) as total'))
            ->where('kode_kecamatan', '!=', null)
            ->where('kode_kecamatan', '!=', 0)
            ->groupBy('kode_kecamatan')
            ->orderBy('total', 'desc')
            ->limit(20)
            ->get();
        $pasiens_kabupaten = PasienDB::select('kode_kabupaten', DB::raw('count(*) as total'))
            ->where('kode_kabupaten', '!=', null)
            ->where('kode_kabupaten', '!=', 0)
            ->groupBy('kode_kabupaten')
            ->orderBy('total', 'desc')
            ->limit(20)
            ->get();
        $pasiens_pendidikan = PasienDB::select('pendidikan', DB::raw('count(*) as total'))
            ->where('pendidikan', '!=', null)
            ->where('pendidikan', '!=', 0)
            ->groupBy('pendidikan')
            ->orderBy('total', 'desc')
            ->get();
        $pendidikan = Pendidikan::get();
        $pasiens_pekerjaan = PasienDB::select('pekerjaan', DB::raw('count(*) as total'))
            ->where('pekerjaan', '!=', null)
            ->where('pekerjaan', '!=', 0)
            ->groupBy('pekerjaan')
            ->orderBy('total', 'desc')
            ->get();
        $pekerjaan = Pekerjaan::get();
        $pasiens_agama = PasienDB::select('agama', DB::raw('count(*) as total'))
            ->where('agama', '!=', null)
            ->where('agama', '!=', 0)
            ->groupBy('agama')
            ->orderBy('total', 'desc')
            ->get();
        $agama = Agama::get();
        // dd($pasiens_pekerjaan);
        // dd($pasiens_pendidikan->where('pendidikan', 15)->first()->total);
        // dd($pasiens_pendidikan);
        $pasiens_laki = PasienDB::where('jenis_kelamin', 'L')->count();
        $pasiens_perempuan = PasienDB::where('jenis_kelamin', 'P')->count();

        return view('simrs.pasien_daerah', compact([
            'pasiens_kecamatan',
            'pasiens_kabupaten',
            'pasiens_laki',
            'pasiens_perempuan',
            'pendidikan',
            'pasiens_pendidikan',
            'pasiens_pekerjaan',
            'pekerjaan',
            'pasiens_agama',
            'agama',
        ]));
    }
}
