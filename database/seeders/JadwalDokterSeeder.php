<?php

namespace Database\Seeders;

use App\Http\Controllers\API\AntrianAPIController;
use Illuminate\Http\Request;
use Carbon\Carbon;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class JadwalDokterSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run(Request $request)
    {
        $now = Carbon::now();
        $request['tanggal'] = $now->format('Y-m-d');
        $polis = ["INT", "ANA", "MAT", "OBG"];
        $api = new AntrianAPIController();
        foreach ($polis as  $value) {
            $request['kodepoli'] = $value;
            $api->ref_jadwal_dokter($request);
        }
    }
}
