<?php

namespace App\Http\Controllers;

use App\Http\Controllers\API\WhatsappController;
use App\Models\AntrianDB;
use App\Models\UnitDB;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use RealRashid\SweetAlert\Facades\Alert;

class AntrianWAController extends Controller
{
    //
    public function index(Request $request)
    {
        if (is_null($request->tanggal)) {
            $request['tanggal'] = Carbon::today()->format('Y-m-d');
        }
        $antrians = AntrianDB::with(['unit'])
            ->whereDate('tanggal', Carbon::parse($request->tanggal)->format('Y-m-d'))
            ->get();
        $poli = UnitDB::where('kelas_unit', 1)
            ->where('ACT', 1)
            ->pluck('nama_unit', 'kode_unit')->toArray();
        $sisa_antrian = AntrianDB::whereDate('tanggal', Carbon::parse($request->tanggal)->format('Y-m-d'))
            ->where('status', 1)
            ->count();
        return view('simrs.antrian_pendaftaranwa', [
            'poli' => $poli,
            'antrians' => $antrians,
            'request' => $request,
            'sisa_antrian' => $sisa_antrian
        ]);
    }
    public function tampil(Request $request)
    {
        if (is_null($request->tanggal)) {
            $request['tanggal'] = Carbon::today()->format('Y-m-d');
        }
        $antrians = AntrianDB::whereDate('tanggal', Carbon::parse($request->tanggal)->format('Y-m-d'))
            ->orderBy('status', 'ASC')
            ->get();
        $poli = UnitDB::where('kelas_unit', 1)
            ->where('ACT', 1)
            ->pluck('nama_unit', 'kode_unit')->toArray();
        $sisa_antrian = AntrianDB::whereDate('tanggal', Carbon::parse($request->tanggal)->format('Y-m-d'))
            ->where('status', 1)
            ->count();
        return view('antrian::antrian_online_tampil', [
            'poli' => $poli,
            'antrians' => $antrians,
            'request' => $request,
            'sisa_antrian' => $sisa_antrian
        ]);
    }
    public function panggil($tanggal, $urutan, $loket, $lantai, Request $request)
    {
        $tanggal = Carbon::parse($tanggal)->format('Y-m-d');
        //panggil urusan simrs
        $antrian = AntrianDB::whereDate('tanggal', $tanggal)
            ->where('status', 1)
            ->where('no_urut', $urutan)->first();
        if (empty($antrian)) {
            Alert::error('Error', 'Belum ada antrian berikutnya');
            return redirect()->route('antrianwa.index', [
                'tanggal' => $tanggal,
                'loket' => $loket,
                'lantai' => $lantai
            ]);
        } else {
            //panggil urusan mesin antrian
            try {
                $mesin_antrian = DB::connection('mysql3')->table('tb_counter')
                    ->where('tgl', $tanggal)
                    ->where('kategori', 'WA')
                    ->where('loket', $loket)
                    ->where('lantai', $lantai)
                    ->get();
                if ($mesin_antrian->count() < 1) {
                    $mesin_antrian = DB::connection('mysql3')->table('tb_counter')->insert([
                        'tgl' => $tanggal,
                        'kategori' => 'WA',
                        'loket' => $loket,
                        'counterloket' => $urutan,
                        'lantai' => $lantai,
                        'mastercount' => $urutan,
                        'sound' => 'PLAY',
                    ]);
                } else {
                    DB::connection('mysql3')->table('tb_counter')
                        ->where('tgl', $tanggal)
                        ->where('kategori', 'WA')
                        ->where('loket', $loket)
                        ->where('lantai', $lantai)
                        ->limit(1)
                        ->update([
                            // 'counterloket' => $antrian->first()->mastercount + 1,
                            'counterloket' => $urutan,
                            // 'mastercount' => $antrian->first()->mastercount + 1,
                            'mastercount' => $urutan,
                            'sound' => 'PLAY',
                        ]);
                }
            } catch (\Throwable $th) {
                Alert::error('Error', 'Mesin Antrian Tidak Menyala');
                return redirect()->route('antrianwa.index', [
                    'tanggal' => $tanggal,
                    'loket' => $loket,
                    'lantai' => $lantai
                ]);
            }
            $antrian->update([
                'status' => 2
            ]);
            //panggil urusan whatsapp
            try {
                $api = new WhatsappController();
                $request['message'] = "Panggilan Antrian Whatsapp Online kepada \n\n *No. Urut :* " . $antrian->no_urut . " \n *Nama :* " . $antrian->nama_antrian . " \n *No. HP :* " . $antrian->phone  . " \n *Kode Antrian :* " . $antrian->kode_antrian .  " \n *Tanggal :* " . Carbon::parse($antrian->tanggal)->isoFormat('dddd, D MMMM Y') . "\n\nSilahkan untuk dapat ke *Loket Pendaftaran Online* dengan menunjukan pesan ini. Apabila belum dapat memenuhi panggilan ke Loket Pendaftaran maka nomor antrian anda akan dilewat dan mengambil ulang antrian.";
                $request['number'] = $antrian->phone;
                $api->send_message($request);
            } catch (\Throwable $th) {
                Alert::error('Error', 'Pesan Whatsapp Gagal Dikirim');
                return redirect()->route('antrianwa.index', [
                    'tanggal' => $tanggal,
                    'loket' => $loket,
                    'lantai' => $lantai
                ]);
            }
            Alert::success('Success', 'Pengirimiman pesan panggilan antrian berhasil');
            return redirect()->route('antrianwa.index', [
                'tanggal' => $tanggal,
                'loket' => $loket,
                'lantai' => $lantai
            ]);
        }
    }
    public function panggil_ulang($tanggal, $urutan, $loket, $lantai, Request $request)
    {
        $tanggal = Carbon::parse($tanggal)->format('Y-m-d');
        //panggil urusan simrs
        $antrian = AntrianDB::whereDate('tanggal', $tanggal)
            ->where('no_urut', $urutan)->first();
        if (empty($antrian)) {
            Alert::error('Error', 'Belum ada antrian berikutnya');
            return redirect()->route('antrianwa.index');
        } else {
            //panggil ulang urusan mesin antrian
            try {
                DB::connection('mysql3')->table('tb_counter')
                    ->where('tgl', $tanggal)
                    ->where('kategori', 'WA')
                    ->where('loket', $loket)
                    ->where('lantai', $lantai)
                    ->limit(1)
                    ->update([
                        'counterloket' => $urutan,
                        'sound' => 'PLAY',
                    ]);
            } catch (\Throwable $th) {
                Alert::error('Error', 'Mesin Antrian Tidak Menyala');
                return redirect()->route('antrianwa.index', [
                    'tanggal' => $tanggal,
                    'loket' => $loket,
                    'lantai' => $lantai
                ]);
            }
            $antrian->update([
                'status' => 2
            ]);
            //panggil ulang urusan whatsapp
            try {
                $api = new WhatsappController;
                $request['message'] = "Panggilan Antrian Whatsapp Online kepada \n\n *No. Urut :* " . $antrian->no_urut . " \n *Nama :* " . $antrian->nama_antrian . " \n *No. HP :* " . $antrian->phone  . " \n *Kode Antrian :* " . $antrian->kode_antrian .  " \n *Tanggal :* " . Carbon::parse($antrian->tanggal)->isoFormat('dddd, D MMMM Y') . "\n\nSilahkan untuk dapat ke *Loket Pendaftaran Online* dengan menunjukan pesan ini. Apabila belum dapat memenuhi panggilan ke Loket Pendaftaran maka nomor antrian anda akan dilewat dan mengambil ulang antrian.";
                $request['number'] = $antrian->phone;
                $api->send_message($request);
            } catch (\Throwable $th) {
                Alert::error('Error', 'Pesan Whatsapp Gagal Dikirim');
                return redirect()->route('antrianwa.index', [
                    'tanggal' => $tanggal,
                    'loket' => $loket,
                    'lantai' => $lantai
                ]);
            }
            Alert::success('Success', 'Pengirimiman pesan panggilan antrian berhasil');
            return redirect()->route('antrianwa.index', [
                'tanggal' => $tanggal,
                'loket' => $loket,
                'lantai' => $lantai
            ]);
        }
    }
    public function selesai($tanggal, $urutan, Request $request)
    {
        $antrian = AntrianDB::whereDate('tanggal', Carbon::parse($tanggal)->format('Y-m-d'))
            ->where('no_urut', $urutan)->first();
        if (empty($antrian)) {
            Alert::error('Error', 'Antrian tidak ditemukan');
            return redirect()->route('antrianwa.index');
        } else {
            $antrian->update([
                'status' => 3
            ]);
            $api = new WhatsappController;
            $request['contenttext'] = "Terima kasih anda telah melakukan pendaftaran antrian melalui layanan Whatsapp. Silahkan untuk dapat langsung ke poliklinik yang dituju. Terima kasih. \n\nSilahakan pilih dibawah ini untuk menilai layanan kami.";
            $request['footertext'] = 'Silahkan klik tombol dibawah ini untuk menilai pelayanan kami.';
            $request['buttonid'] = 'id1, id2';
            $request['buttontext'] = 'SANGAT MEMBANTU, TOLONG PERBAIKI';
            $request['number'] = $antrian->phone;
            $api->send_button($request);
            Alert::success('Success', 'Pengirimiman pesan panggilan antrian berhasil');
            return redirect()->back();
        }
    }
    public function batal($tanggal, $urutan, Request $request)
    {
        $antrian = AntrianDB::whereDate('tanggal', Carbon::parse($tanggal)->format('Y-m-d'))
            ->where('no_urut', $urutan)->first();
        if (empty($antrian)) {
            Alert::error('Error', 'Antrian tidak ditemukan');
            return redirect()->route('antrianwa.index');
        } else {
            $antrian->update([
                'status' => 98
            ]);
            $api = new WhatsappController;
            $request['contenttext'] = 'Mohon maaf dikarenakan tidak memenuhi panggilan antrian atas nama *' . $antrian->nama_antrian . '* dengan nomor urut *' . $antrian->no_urut . "*, maka nomor antrian anda dinyatakan dibatalkan. Terima kasih atas kepercayaan Anda.";
            $request['footertext'] = 'Silahkan klik tombol dibawah ini untuk konfirmasi pembatalan antrian anda.';
            $request['buttonid'] = 'id1, id2';
            $request['buttontext'] = 'BATAL-ANTRIAN#' . $antrian->kode_antrian . ' , DAFTAR-ULANG#' . $antrian->kode_antrian;
            $request['number'] = $antrian->phone;
            $api->send_button($request);
            Alert::success('Success', 'Pengirimiman pesan batal antrian berhasil');
            return  redirect()->back();
        }
    }
    public function store(Request $request)
    {
        $request['tanggal'] = Carbon::parse($request->tanggal)->format('Y-m-d');
        $request['kode_antrian'] = random_int(1, 999999999);

        $request->validate([
            'kode_antrian' => 'required|unique:mysql2.mw_antrian,kode_antrian,' . $request->id,
            'tanggal' => 'required',
            'nik' => 'required',
            'nama' => 'required',
            'phone' => 'required',
            'kode_poli' => 'required',
            'tipe' => 'required',
        ]);

        $antrian = AntrianDB::create([
            'kode_antrian' => $request->kode_antrian,
            'tanggal' => $request->tanggal,
            'nik' => $request->nik,
            'nama' => $request->nama,
            'phone' => $request->phone,
            'kode_poli' => $request->kode_poli,
            'status' => 1,
            'tipe' => $request->tipe,
        ]);

        Alert::success('Success Info', 'Success Message');
        return redirect()->route('antrianwa.index');
    }
    public function daftar(Request $request)
    {
        dd($request->all());
    }
    public function poliklinik(Request $request)
    {
        if (is_null($request->tanggal)) {
            $request['tanggal'] = Carbon::today()->format('Y-m-d');
        } else {
            $request['tanggal'] = Carbon::parse($request->tanggal)->format('Y-m-d');
        }
        $units = UnitDB::where('kelas_unit', 1)
            ->where('ACT', 1)
            ->get();
        $antrians_jumlah  = AntrianDB::whereDate('tanggal', $request->tanggal)->count();
        return view('antrian::antrian_unit_index', [
            'units' => $units,
            'request' => $request,
            'antrians_jumlah' => $antrians_jumlah
        ]);
    }
    public function jadwal_poli(Request $request)
    {
        $jadwals = JadwalPoliDB::with(['unit', 'dokter'])->get();
        $polikliniks = UnitDB::where('kelas_unit', 1)
            ->where('ACT', 1)
            ->pluck('nama_unit', 'kode_unit')->toArray();
        $dokters = ParamedisDB::where('keilmuan', 'dr')
            ->pluck('nama_paramedis', 'kode_paramedis')->toArray();
        return view('antrian::antrian_jadwal_poli_index', [
            'request' => $request,
            'jadwals' => $jadwals,
            'polikliniks' => $polikliniks,
            'dokters' => $dokters,
        ]);
    }
    public function jadwal_poli_libur(Request $request)
    {
        $jadwals = JadwalLiburPoliDB::with(['unit', 'antrians'])
            ->paginate();
        $polikliniks = UnitDB::where('kelas_unit', 1)
            ->where('ACT', 1)
            ->pluck('nama_unit', 'kode_unit')->toArray();
        return view('antrian::antrian_jadwal_libur_poli_index', [
            'request' => $request,
            'jadwals' => $jadwals,
            'polikliniks' => $polikliniks
        ]);
    }
}
